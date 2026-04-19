/// Embedding module — only compiled with `--features embedding`
/// Model: all-MiniLM-L6-v2 (ONNX, int8 quantized, ~22MB)

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const MODEL_URL: &str = "https://huggingface.co/Supabase/all-MiniLM-L6-v2/resolve/main/onnx/model_quantized.onnx";
const TOKENIZER_URL: &str = "https://huggingface.co/Supabase/all-MiniLM-L6-v2/resolve/main/tokenizer.json";
pub const MODEL_DIM: usize = 384;
pub const MODEL_VERSION: &str = "minilm-l6-v2-int8";

pub fn model_dir() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".kiro").join("models")
}
pub fn model_path() -> PathBuf { model_dir().join("model_quantized.onnx") }
pub fn tokenizer_path() -> PathBuf { model_dir().join("tokenizer.json") }

pub fn is_model_downloaded() -> bool {
    let mp = model_path();
    let tp = tokenizer_path();
    mp.exists() && tp.exists()
        && mp.metadata().map(|m| m.len() > 1_000_000).unwrap_or(false)  // Model should be >1MB
        && tp.metadata().map(|m| m.len() > 1000).unwrap_or(false)
}

pub fn download_model() -> Result<PathBuf> {
    let dir = model_dir();
    std::fs::create_dir_all(&dir)?;
    if !model_path().exists() {
        eprintln!("Downloading embedding model (~22MB)...");
        download_file(MODEL_URL, &model_path())?;
        eprintln!("✅ Model downloaded");
    }
    if !tokenizer_path().exists() {
        eprintln!("Downloading tokenizer...");
        download_file(TOKENIZER_URL, &tokenizer_path())?;
        eprintln!("✅ Tokenizer downloaded");
    }
    Ok(dir)
}

fn download_file(url: &str, dest: &Path) -> Result<()> {
    let output = std::process::Command::new("curl")
        .args(["-sL", "--fail", "-o", dest.to_str().unwrap(), url])
        .output()
        .context("curl not found — install curl to download the model")?;
    if !output.status.success() {
        // Remove partial/error file
        let _ = std::fs::remove_file(dest);
        anyhow::bail!("Download failed (HTTP error): {}", String::from_utf8_lossy(&output.stderr));
    }
    // Verify file is not tiny (error page)
    let size = std::fs::metadata(dest).map(|m| m.len()).unwrap_or(0);
    if size < 1000 {
        let _ = std::fs::remove_file(dest);
        anyhow::bail!("Downloaded file too small ({}B) — likely an error page", size);
    }
    Ok(())
}

pub struct Encoder {
    session: ort::session::Session,
    tokenizer: tokenizers::Tokenizer,
}

impl Encoder {
    pub fn load() -> Result<Self> {
        if !is_model_downloaded() {
            anyhow::bail!("Model not downloaded or corrupt. Run: kiro-cortex memory init");
        }
        let mp = model_path();
        let model_size = mp.metadata().map(|m| m.len()).unwrap_or(0);
        if model_size < 1_000_000 {
            anyhow::bail!("Model file corrupt ({} bytes). Delete ~/.kiro/models/ and run: kiro-cortex memory init", model_size);
        }
        let session = ort::session::Session::builder()?
            .commit_from_file(&mp)
            .context("Failed to load ONNX model — file may be corrupt. Delete ~/.kiro/models/ and re-run: kiro-cortex memory init")?;
        let tokenizer = tokenizers::Tokenizer::from_file(tokenizer_path())
            .map_err(|e| anyhow::anyhow!("Failed to load tokenizer: {}", e))?;
        Ok(Self { session, tokenizer })
    }

    pub fn encode(&mut self, text: &str) -> Result<Vec<f32>> {
        let encoding = self.tokenizer.encode(text, true)
            .map_err(|e| anyhow::anyhow!("Tokenize error: {}", e))?;

        let ids: Vec<i64> = encoding.get_ids().iter().map(|&id| id as i64).collect();
        let mask: Vec<i64> = encoding.get_attention_mask().iter().map(|&m| m as i64).collect();
        let type_ids: Vec<i64> = encoding.get_type_ids().iter().map(|&t| t as i64).collect();
        let seq_len = ids.len();

        // Create tensors using (shape, Vec<T>) tuple — no ndarray needed
        let ids_t = ort::value::Tensor::from_array(([1usize, seq_len], ids))?;
        let mask_t = ort::value::Tensor::from_array(([1usize, seq_len], mask))?;
        let type_t = ort::value::Tensor::from_array(([1usize, seq_len], type_ids))?;

        let outputs = self.session.run(ort::inputs![
            "input_ids" => ids_t,
            "attention_mask" => mask_t,
            "token_type_ids" => type_t,
        ])?;

        // Extract output float data — downcast Value to Tensor
        let output = &outputs[0];
        let tensor_ref = output.downcast_ref::<ort::value::TensorValueType<f32>>()
            .context("Output is not a float tensor")?;
        let (shape, data) = tensor_ref.try_extract_tensor::<f32>()?;
        let actual_seq = if shape.len() >= 2 { shape[1] as usize } else { seq_len };

        // Mean pooling
        let mut pooled = vec![0.0f32; MODEL_DIM];
        for i in 0..actual_seq {
            for j in 0..MODEL_DIM {
                let idx = i * MODEL_DIM + j;
                if idx < data.len() { pooled[j] += data[idx]; }
            }
        }
        for v in &mut pooled { *v /= actual_seq as f32; }

        // L2 normalize
        let norm: f32 = pooled.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 { for v in &mut pooled { *v /= norm; } }

        Ok(pooled)
    }

    pub fn encode_to_bytes(&mut self, text: &str) -> Result<Vec<u8>> {
        Ok(self.encode(text)?.iter().flat_map(|f| f.to_le_bytes()).collect())
    }
}

/// Return model metadata for benchmark reports
pub fn model_info() -> std::collections::HashMap<String, String> {
    let mut info = std::collections::HashMap::new();
    info.insert("model_version".into(), MODEL_VERSION.into());
    info.insert("model_dim".into(), MODEL_DIM.to_string());
    let mp = model_path();
    if mp.exists() {
        info.insert("model_size_bytes".into(), mp.metadata().map(|m| m.len().to_string()).unwrap_or_default());
        // SHA256 of model file
        use sha2::{Digest, Sha256};
        if let Ok(data) = std::fs::read(&mp) {
            let hash = Sha256::digest(&data);
            info.insert("model_sha256".into(), format!("{:x}", hash));
        }
    }
    info.insert("downloaded".into(), is_model_downloaded().to_string());
    info
}

pub fn cosine_similarity(a: &[u8], b: &[u8]) -> f32 {
    if a.len() != b.len() || a.len() != MODEL_DIM * 4 { return 0.0; }
    let a_f: Vec<f32> = a.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    let b_f: Vec<f32> = b.chunks_exact(4).map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    a_f.iter().zip(b_f.iter()).map(|(x, y)| x * y).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_identical() {
        let mut v = vec![0.0f32; MODEL_DIM]; v[0] = 1.0;
        let b: Vec<u8> = v.iter().flat_map(|f| f.to_le_bytes()).collect();
        assert!((cosine_similarity(&b, &b) - 1.0).abs() < 0.001);
    }

    #[test]
    fn cosine_orthogonal() {
        let mut a = vec![0.0f32; MODEL_DIM]; a[0] = 1.0;
        let mut b = vec![0.0f32; MODEL_DIM]; b[1] = 1.0;
        let ab: Vec<u8> = a.iter().flat_map(|f| f.to_le_bytes()).collect();
        let bb: Vec<u8> = b.iter().flat_map(|f| f.to_le_bytes()).collect();
        assert!(cosine_similarity(&ab, &bb).abs() < 0.001);
    }
}

#![cfg_attr(not(test), allow(dead_code))]

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
pub struct HookEvent {
    pub hook_event_name: String,
    pub cwd: String,
    pub session_id: String,
    pub tool_name: Option<String>,
    pub tool_input: Option<Value>,
    pub tool_response: Option<Value>,
    pub prompt: Option<String>,
}

impl HookEvent {
    pub fn from_stdin() -> Result<Self> {
        let stdin = std::io::stdin();
        serde_json::from_reader(stdin.lock()).context("Failed to parse HookEvent from stdin")
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).context("Failed to parse HookEvent JSON")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_agent_spawn() {
        let json = r#"{"hook_event_name":"agentSpawn","cwd":"/tmp","session_id":"abc-123"}"#;
        let event = HookEvent::from_json(json).unwrap();
        assert_eq!(event.hook_event_name, "agentSpawn");
        assert_eq!(event.cwd, "/tmp");
        assert_eq!(event.session_id, "abc-123");
        assert!(event.tool_name.is_none());
        assert!(event.prompt.is_none());
    }

    #[test]
    fn parse_pre_tool_use() {
        let json = r#"{
            "hook_event_name": "preToolUse",
            "cwd": "/project",
            "session_id": "s-1",
            "tool_name": "read",
            "tool_input": {"operations": [{"mode": "Line", "path": "/project/.env"}]}
        }"#;
        let event = HookEvent::from_json(json).unwrap();
        assert_eq!(event.hook_event_name, "preToolUse");
        assert_eq!(event.tool_name.as_deref(), Some("read"));
        assert!(event.tool_input.is_some());
        assert!(event.tool_response.is_none());
    }

    #[test]
    fn parse_post_tool_use() {
        let json = r#"{
            "hook_event_name": "postToolUse",
            "cwd": "/project",
            "session_id": "s-1",
            "tool_name": "read",
            "tool_input": {"operations": [{"path": "/project/file.txt"}]},
            "tool_response": {"success": true, "result": ["hello"]}
        }"#;
        let event = HookEvent::from_json(json).unwrap();
        assert_eq!(event.hook_event_name, "postToolUse");
        assert!(event.tool_response.is_some());
    }

    #[test]
    fn parse_user_prompt_submit() {
        let json = r#"{
            "hook_event_name": "userPromptSubmit",
            "cwd": "/project",
            "session_id": "s-1",
            "prompt": "Read the .env file"
        }"#;
        let event = HookEvent::from_json(json).unwrap();
        assert_eq!(event.prompt.as_deref(), Some("Read the .env file"));
    }

    #[test]
    fn parse_malformed_json() {
        let result = HookEvent::from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn parse_empty_json() {
        let result = HookEvent::from_json("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_extra_fields_ignored() {
        let json = r#"{
            "hook_event_name": "agentSpawn",
            "cwd": "/tmp",
            "session_id": "s-1",
            "unknown_field": "should be ignored",
            "another": 42
        }"#;
        let event = HookEvent::from_json(json).unwrap();
        assert_eq!(event.hook_event_name, "agentSpawn");
    }
}

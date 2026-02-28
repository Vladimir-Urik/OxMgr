use anyhow::Result;

use crate::ipc::IpcResponse;

pub(crate) fn expect_ok(response: IpcResponse) -> Result<IpcResponse> {
    if response.ok {
        Ok(response)
    } else {
        anyhow::bail!(response.message)
    }
}

#[cfg(test)]
mod tests {
    use super::expect_ok;
    use crate::ipc::IpcResponse;

    #[test]
    fn expect_ok_returns_response_when_ok() {
        let response = IpcResponse::ok("all good");

        let result = expect_ok(response.clone()).expect("expected successful response");

        assert!(result.ok);
        assert_eq!(result.message, "all good");
    }

    #[test]
    fn expect_ok_returns_message_as_error_when_response_failed() {
        let err = expect_ok(IpcResponse::error("daemon unavailable"))
            .expect_err("expected failed response to become an error");

        assert_eq!(err.to_string(), "daemon unavailable");
    }
}

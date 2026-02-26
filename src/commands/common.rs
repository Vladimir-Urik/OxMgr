use anyhow::Result;

use crate::ipc::IpcResponse;

pub(crate) fn expect_ok(response: IpcResponse) -> Result<IpcResponse> {
    if response.ok {
        Ok(response)
    } else {
        anyhow::bail!(response.message)
    }
}

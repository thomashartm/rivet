//! Container tests: they need the databases of `docker/compose.test.yml`.
//! Without `RIVET_TEST_CONTAINERS=1` each test is skipped and passes.

use rivet_sdk::error::Result;
use rivet_testkit::database::{containers_enabled, mysql, postgres};

#[tokio::test]
async fn postgres_container_is_reachable() -> Result<()> {
    if !containers_enabled() {
        return Ok(());
    }
    postgres().ensure_reachable().await
}

#[tokio::test]
async fn mysql_container_is_reachable() -> Result<()> {
    if !containers_enabled() {
        return Ok(());
    }
    mysql().ensure_reachable().await
}

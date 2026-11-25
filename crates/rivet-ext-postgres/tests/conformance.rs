//! The conformance suite of `rivet-testkit` against the PostgreSQL container.
//! Skipped (and says so) unless `RIVET_TEST_CONTAINERS=1`.

use rivet_ext_postgres::PostgresDriver;
use rivet_testkit::conformance::{self, Sql};
use rivet_testkit::database;

#[tokio::test(flavor = "multi_thread")]
async fn postgres_driver_passes_the_conformance_suite() {
    if !database::containers_enabled() {
        return;
    }
    let fixture = database::postgres();
    fixture.ensure_reachable().await.unwrap();
    conformance::run_all(&PostgresDriver, &fixture, &Sql::postgres())
        .await
        .unwrap();
}

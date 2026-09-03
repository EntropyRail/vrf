import { PostgresOperatorStore } from "../../operator/postgres-store.mjs";

if (process.env.VRF_TEST_STORE_IDENTITY) {
  const identity = JSON.parse(process.env.VRF_TEST_STORE_IDENTITY);
  const store = await PostgresOperatorStore.connect({
    databaseUrl: process.env.VRF_TEST_DATABASE_URL,
    identity,
  });
  await store.withRelayerNonceLock(process.env.VRF_TEST_RELAYER, async () => {
    process.stdout.write("LOCKED\n");
    await new Promise(() => {});
  });
}

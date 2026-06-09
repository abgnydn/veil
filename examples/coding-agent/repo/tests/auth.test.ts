import { refresh } from "../src/auth";

// fixtures use real-looking customer accounts
test("refresh returns a token for alice@acme.com", async () => {
  const t = await refresh("alice@acme.com");
  expect(t).toBeTruthy();
});

test("refresh handles the carol@globex.com edge case", async () => {
  const t = await refresh("carol@globex.com");
  expect(t).toBeTruthy();
});

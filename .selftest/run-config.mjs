import { loadHydraConfig } from "./build/config.js";

let failures = 0;
const check = (label, cond) => {
  console.log(`${cond ? "PASS" : "FAIL"}  ${label}`);
  if (!cond) failures++;
};

// defaults, no env, no overrides
delete process.env.HYDRA_BASE_URL;
delete process.env.HYDRA_TOKEN;
{
  const cfg = loadHydraConfig();
  check("default baseUrl", cfg.baseUrl === "http://127.0.0.1:8443");
  check("default token", cfg.token === "local-development-token-32-bytes");
  check("default namespace", cfg.namespace === "default");
}

// env var takes effect
process.env.HYDRA_BASE_URL = "http://example.com:9999";
{
  const cfg = loadHydraConfig();
  check("env var overrides default", cfg.baseUrl === "http://example.com:9999");
}

// explicit override wins over env
{
  const cfg = loadHydraConfig({ baseUrl: "http://explicit.example" });
  check("explicit override wins over env var", cfg.baseUrl === "http://explicit.example");
}

delete process.env.HYDRA_BASE_URL;

console.log();
if (failures > 0) {
  console.error(`${failures} FAILURE(S)`);
  process.exit(1);
}
console.log("ALL CONFIG CHECKS PASSED");

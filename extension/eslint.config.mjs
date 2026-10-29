import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "node_modules"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    languageOptions: { globals: { ...globals.browser, ...globals.node, chrome: "readonly" } },
    rules: {
      // Reasons and hosts come from the network; they only ever go in as text.
      "no-restricted-properties": [
        "error",
        { property: "innerHTML", message: "Use textContent." },
        { property: "outerHTML", message: "Use textContent." },
        { property: "insertAdjacentHTML", message: "Build nodes with textContent." },
      ],
    },
  },
);

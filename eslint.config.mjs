import globals from "globals";
import pluginJs from "@eslint/js";

export default [
  {
    languageOptions: {
      globals: globals.browser,
    },
  },
  pluginJs.configs.recommended,
  {
    ignores: [
      "database/**",
      "instance/**",
      "migrations/**",
      "node_modules/**",
      "ScratchFolder/**",
      "Templates/**",
      ".venv/**",
    ],
  },
];


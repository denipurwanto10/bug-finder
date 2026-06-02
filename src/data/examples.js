// data/examples.js
export const EXAMPLES = [
  {
    label: "Null Access",
    lang: "javascript",
    code: `const data = undefined;\nconsole.log(data.name);\n// TypeError: Cannot read properties of undefined`,
  },
  {
    label: "Infinite Loop",
    lang: "javascript",
    code: `let i = 0;\nwhile (i < 10) {\n  console.log(i);\n  // forgot: i++\n}`,
  },
  {
    label: "Array Off-by-one",
    lang: "javascript",
    code: `const arr = [1, 2, 3];\nfor (let i = 0; i <= arr.length; i++) {\n  console.log(arr[i]);\n}`,
  },
  {
    label: "Promise Not Awaited",
    lang: "javascript",
    code: `async function fetchUser() {\n  const res = fetch('https://api.example.com/user');\n  return res.json();\n}`,
  },
];
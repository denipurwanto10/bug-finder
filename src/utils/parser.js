// utils/parser.js
export function parseBugs(text) {
  // Try to extract JSON array from the response
  try {
    const jsonMatch = text.match(/```json\s*([\s\S]*?)```/);
    if (jsonMatch) return JSON.parse(jsonMatch[1]);
    const arrMatch = text.match(/\[[\s\S]*\]/);
    if (arrMatch) return JSON.parse(arrMatch[0]);
  } catch (e) {
    console.error('Failed to parse bugs:', e);
  }
  return null;
}
import React, { useState } from 'react';
import { globalStyles } from './styles/globalStyles.js';
import Header from './components/Header.jsx';     
import CodeEditor from './components/CodeEditor.jsx';   
import ResultPanel from './components/ResultPanel.jsx'; 
import { EXAMPLES } from './data/examples.js';
import { parseBugs } from './utils/parser.js';

// PAKAI API KEY AQ. ANDA
const GEMINI_API_KEY = "apikey";

export default function BugFinder() {
  const [code, setCode] = useState("");
  const [lang, setLang] = useState("javascript");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  async function analyzeCode() {
    if (!code.trim()) {
      setResult({ error: "empty" });
      return;
    }
    
    setLoading(true);
    setResult(null);

    const prompt = `You are a code bug detector. Analyze this code and return ONLY a JSON array of bugs.

Language: ${lang}
Code:
${code}

Return format: [{"severity":"critical/warning/info","title":"bug name","description":"what's wrong","fix":"corrected code","explanation":"how to fix"}]

If no bugs, return: []`;

    try {
      // ENDPOINT INI KHUSUS UNTUK KEY FORMAT AQ.

// MENJADI:
const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Goog-Api-Key": GEMINI_API_KEY  // Header khusus untuk key AQ.
        },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { temperature: 0.1, maxOutputTokens: 1024 }
        })
      });

      console.log("Status:", response.status);

      if (!response.ok) {
        const error = await response.text();
        console.error("Error:", error);
        
        if (response.status === 403 || response.status === 401) {
          setResult({ error: "invalid_key", details: "Key AQ. perlu menggunakan header X-Goog-Api-Key" });
        } else {
          setResult({ error: "api_error", details: `HTTP ${response.status}` });
        }
        setLoading(false);
        return;
      }

      const data = await response.json();
      let raw = data.candidates?.[0]?.content?.parts?.[0]?.text || "";
      
      raw = raw.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
      
      let bugs = [];
      const match = raw.match(/\[[\s\S]*\]/);
      if (match) {
        try {
          bugs = JSON.parse(match[0]);
        } catch (e) {}
      }
      
      if (!Array.isArray(bugs)) bugs = [];
      bugs = bugs.filter(b => b.severity && b.title);
      
      setResult({ bugs: bugs });
      
    } catch (error) {
      setResult({ error: "network", details: error.message });
    }
    
    setLoading(false);
  }

  function loadExample(ex) {
    setCode(ex.code);
    setLang(ex.lang);
    setResult(null);
  }

  function clearCode() {
    setCode("");
    setResult(null);
  }

  const counts = result?.bugs ? {
    critical: result.bugs.filter(b => b.severity === "critical").length,
    warning: result.bugs.filter(b => b.severity === "warning").length,
    info: result.bugs.filter(b => b.severity === "info").length,
  } : null;

  return (
    <>
      <style>{globalStyles}</style>
      <div className="app">
        <div className="noise" />
        <div className="grid-bg" />
        <div className="glow-orb orb1" />
        <div className="glow-orb orb2" />

        <div className="container">
          <Header />
          
          <div className="main-grid">
            <CodeEditor
              code={code}
              setCode={setCode}
              lang={lang}
              setLang={setLang}
              onClear={clearCode}
              onAnalyze={analyzeCode}
              loading={loading}
              examples={EXAMPLES}
              onLoadExample={loadExample}
            />
            
            <ResultPanel
              result={result}
              loading={loading}
              counts={counts}
            />
          </div>
        </div>
      </div>
    </>
  );
}
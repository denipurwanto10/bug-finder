// components/CodeEditor.js
import React, { useRef } from 'react';

export default function CodeEditor({ code, setCode, lang, setLang, onClear, onAnalyze, loading, examples, onLoadExample }) {
  const textareaRef = useRef(null);
  const lines = code.split("\n");
  const lineCount = Math.max(lines.length, 14);
  
  const languages = ["javascript", "typescript", "python", "java", "php", "go", "rust", "c", "cpp"];

  const handleTab = (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const s = e.target.selectionStart;
      const end = e.target.selectionEnd;
      const newCode = code.substring(0, s) + "  " + code.substring(end);
      setCode(newCode);
      setTimeout(() => {
        e.target.selectionStart = e.target.selectionEnd = s + 2;
      }, 0);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <div className="traffic">
            <div className="tl red" />
            <div className="tl yellow" />
            <div className="tl green" />
          </div>
          <span style={{ marginLeft: 6 }}>
            <span className="dot" /> &nbsp;INPUT
          </span>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <select
            className="lang-select"
            value={lang}
            onChange={(e) => setLang(e.target.value)}
          >
            {languages.map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
          {code && (
            <button className="clear-btn" onClick={onClear}>
              clear
            </button>
          )}
        </div>
      </div>

      <div className="editor-wrap">
        <div className="editor-inner">
          <div className="line-nums">
            {Array.from({ length: lineCount }, (_, i) => (
              <div className="line-num" key={i}>{i + 1}</div>
            ))}
          </div>
          <textarea
            ref={textareaRef}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={"// Paste your code here...\n// AI will find bugs & suggest fixes"}
            spellCheck={false}
            onKeyDown={handleTab}
          />
        </div>
      </div>

      <div className="example-row">
        <span className="example-label">EXAMPLES:</span>
        {examples.map((ex) => (
          <button key={ex.label} className="chip" onClick={() => onLoadExample(ex)}>
            {ex.label}
          </button>
        ))}
      </div>

      <button
        className={`analyze-btn${loading ? " loading" : ""}`}
        onClick={onAnalyze}
        disabled={loading || !code.trim()}
      >
        {loading ? (
          <>
            <div className="spinner" />
            Analyzing...
          </>
        ) : (
          <>
            <span>🔍</span> Analyze Code
          </>
        )}
      </button>
    </div>
  );
}
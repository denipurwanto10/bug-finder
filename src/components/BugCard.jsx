// components/BugCard.js
import React from 'react';

export default function BugCard({ bug, index }) {
  const severity = bug.severity || "info";
  const severityIcon = {
    critical: "🔴",
    warning: "🟡",
    info: "🟢"
  }[severity];

  return (
    <div
      className={`bug-card ${severity}`}
      style={{ animationDelay: `${index * 0.08}s` }}
    >
      <div>
        <span className={`bug-label ${severity}`}>
          {severityIcon}&nbsp;{severity.toUpperCase()}
        </span>
      </div>
      <div className="bug-title">{bug.title}</div>
      <div className="bug-desc">{bug.description}</div>
      {bug.fix && (
        <div className="fix-block">
          <div className="fix-label">✦ FIX</div>
          <pre className="fix-code">{bug.fix}</pre>
          {bug.explanation && (
            <div className="fix-explanation">{bug.explanation}</div>
          )}
        </div>
      )}
    </div>
  );
}
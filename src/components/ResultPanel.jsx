// components/ResultPanel.js
import React from 'react';
import BugCard from './BugCard.jsx';

export default function ResultPanel({ result, loading, counts }) {
  const getCounts = () => {
    if (!counts) return null;
    return (
      <div style={{ display: "flex", gap: 6 }}>
        {counts.critical > 0 && (
          <span className="summary-pill critical">🔴 {counts.critical}</span>
        )}
        {counts.warning > 0 && (
          <span className="summary-pill warning">🟡 {counts.warning}</span>
        )}
        {counts.info > 0 && (
          <span className="summary-pill info">🟢 {counts.info}</span>
        )}
      </div>
    );
  };

  const renderContent = () => {
    if (!result && !loading) {
      return (
        <div className="empty-state">
          <span className="empty-icon">🔎</span>
          <p className="empty-text">
            Paste your code on the left<br />then click <strong style={{ color: "#fff" }}>Analyze Code</strong>
          </p>
        </div>
      );
    }

    if (loading) {
      return (
        <div className="empty-state">
          <span style={{ fontSize: 36 }}>⚙️</span>
          <p className="empty-text">Scanning for bugs...</p>
        </div>
      );
    }

    if (result && result.bugs === null) {
      return <div className="stream-text">{result.raw}</div>;
    }

    if (result && result.bugs !== null && result.bugs.length === 0) {
      return (
        <div className="clean-state">
          <span className="clean-icon">✅</span>
          <p className="clean-text">No bugs detected!<br />Your code looks clean.</p>
        </div>
      );
    }

    if (result && result.bugs && result.bugs.length > 0) {
      return result.bugs.map((bug, i) => (
        <BugCard key={i} bug={bug} index={i} />
      ));
    }

    return null;
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <div className="panel-title">
          <div className="dot green" /> &nbsp;RESULT
        </div>
        {getCounts()}
      </div>
      <div className="result-area">
        {renderContent()}
      </div>
    </div>
  );
}
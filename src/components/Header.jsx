// components/Header.js
import React from 'react';

export default function Header() {
  return (
    <div className="header">
      <div className="logo-wrap">
        <span className="logo-icon">🪲</span>
      </div>
      <div className="header-text">
        <h1>Bug Finder</h1>
        <p>// AI-powered code analysis</p>
      </div>
      <span className="badge">AI POWERED</span>
    </div>
  );
}
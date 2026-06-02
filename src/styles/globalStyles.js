// styles/globalStyles.js
import { THEMES } from './theme.js';

export const globalStyles = `
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400&family=Syne:wght@400;600;700;800&display=swap');

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: ${THEMES.bg};
    color: ${THEMES.text};
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
  }

  .app {
    min-height: 100vh;
    background: ${THEMES.bg};
    position: relative;
    overflow-x: hidden;
  }

  .noise {
    position: fixed;
    inset: 0;
    opacity: 0.03;
    pointer-events: none;
    z-index: 0;
    background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='noise'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23noise)'/%3E%3C/svg%3E");
    background-repeat: repeat;
    background-size: 200px;
  }

  .grid-bg {
    position: fixed;
    inset: 0;
    pointer-events: none;
    z-index: 0;
    background-image:
      linear-gradient(rgba(255,77,109,0.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,77,109,0.04) 1px, transparent 1px);
    background-size: 40px 40px;
  }

  .glow-orb {
    position: fixed;
    width: 600px;
    height: 600px;
    border-radius: 50%;
    pointer-events: none;
    z-index: 0;
    filter: blur(120px);
  }

  .orb1 {
    background: rgba(255,77,109,0.07);
    top: -200px;
    right: -100px;
  }

  .orb2 {
    background: rgba(0,229,160,0.05);
    bottom: -200px;
    left: -100px;
  }

  .container {
    position: relative;
    z-index: 1;
    max-width: 1100px;
    margin: 0 auto;
    padding: 40px 24px 80px;
  }

  /* HEADER */
  .header {
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 52px;
  }

  .logo-wrap {
    width: 48px;
    height: 48px;
    background: ${THEMES.accentSoft};
    border: 1px solid ${THEMES.accent};
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 0 24px ${THEMES.accentGlow};
    flex-shrink: 0;
  }

  .logo-icon {
    font-size: 24px;
    line-height: 1;
  }

  .header-text h1 {
    font-size: 26px;
    font-weight: 800;
    letter-spacing: -0.5px;
    color: #fff;
  }

  .header-text p {
    font-size: 13px;
    color: ${THEMES.muted};
    font-family: 'Space Mono', monospace;
    margin-top: 2px;
  }

  .badge {
    margin-left: auto;
    background: ${THEMES.accentSoft};
    border: 1px solid ${THEMES.accentGlow};
    color: ${THEMES.accent};
    font-family: 'Space Mono', monospace;
    font-size: 11px;
    padding: 4px 10px;
    border-radius: 100px;
    letter-spacing: 1px;
  }

  /* MAIN LAYOUT */
  .main-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    align-items: start;
  }

  @media (max-width: 800px) {
    .main-grid { grid-template-columns: 1fr; }
  }

  /* PANEL */
  .panel {
    background: ${THEMES.card};
    border: 1px solid ${THEMES.border};
    border-radius: 16px;
    overflow: hidden;
    transition: border-color 0.2s;
  }

  .panel:hover {
    border-color: #2a2a3e;
  }

  .panel-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 18px;
    border-bottom: 1px solid ${THEMES.border};
    background: ${THEMES.surface};
  }

  .panel-title {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    font-family: 'Space Mono', monospace;
    font-weight: 700;
    color: ${THEMES.muted};
    letter-spacing: 1px;
    text-transform: uppercase;
  }

  .dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: ${THEMES.accent};
    box-shadow: 0 0 6px ${THEMES.accent};
  }

  .dot.green { background: ${THEMES.green}; box-shadow: 0 0 6px ${THEMES.green}; }
  .dot.yellow { background: ${THEMES.yellow}; box-shadow: 0 0 6px ${THEMES.yellow}; }

  /* TRAFFIC LIGHTS */
  .traffic {
    display: flex;
    gap: 6px;
  }

  .tl {
    width: 10px; height: 10px;
    border-radius: 50%;
  }
  .tl.red { background: #ff5f57; }
  .tl.yellow { background: #febc2e; }
  .tl.green { background: #28c840; }

  /* EDITOR */
  .editor-wrap {
    position: relative;
    font-family: 'Space Mono', monospace;
    font-size: 13.5px;
    line-height: 1.7;
  }

  .editor-inner {
    display: flex;
    min-height: 320px;
  }

  .line-nums {
    padding: 16px 0;
    width: 44px;
    text-align: right;
    padding-right: 12px;
    color: ${THEMES.muted};
    font-size: 12px;
    background: ${THEMES.surface};
    border-right: 1px solid ${THEMES.border};
    user-select: none;
    flex-shrink: 0;
  }

  .line-num { height: calc(1.7 * 13.5px); display: flex; align-items: center; justify-content: flex-end; }

  textarea {
    flex: 1;
    background: transparent;
    border: none;
    outline: none;
    color: ${THEMES.text};
    font-family: 'Space Mono', monospace;
    font-size: 13.5px;
    line-height: 1.7;
    padding: 16px;
    resize: none;
    min-height: 320px;
    caret-color: ${THEMES.accent};
  }

  textarea::selection {
    background: rgba(255,77,109,0.2);
  }

  textarea::placeholder {
    color: ${THEMES.muted};
    opacity: 0.5;
  }

  /* LANG SELECTOR */
  .lang-select {
    background: ${THEMES.surface};
    border: 1px solid ${THEMES.border};
    color: ${THEMES.text};
    font-family: 'Space Mono', monospace;
    font-size: 11px;
    padding: 4px 8px;
    border-radius: 6px;
    cursor: pointer;
    outline: none;
  }

  /* ANALYZE BTN */
  .analyze-btn {
    width: 100%;
    padding: 14px 24px;
    background: ${THEMES.accent};
    color: #fff;
    border: none;
    font-family: 'Syne', sans-serif;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 0.5px;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    border-radius: 0 0 16px 16px;
  }

  .analyze-btn:hover:not(:disabled) {
    background: #ff6b85;
    box-shadow: 0 8px 32px rgba(255,77,109,0.4);
    transform: translateY(-1px);
  }

  .analyze-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .analyze-btn.loading {
    background: #222230;
    color: ${THEMES.muted};
    border-radius: 0 0 16px 16px;
  }

  /* SPINNER */
  @keyframes spin { to { transform: rotate(360deg); } }
  .spinner {
    width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,0.2);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  /* RESULT PANEL */
  .result-area {
    padding: 20px;
    min-height: 320px;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 280px;
    gap: 12px;
    color: ${THEMES.muted};
  }

  .empty-icon {
    font-size: 40px;
    opacity: 0.3;
    filter: grayscale(1);
  }

  .empty-text {
    font-size: 13px;
    font-family: 'Space Mono', monospace;
    text-align: center;
    line-height: 1.6;
    opacity: 0.5;
  }

  /* BUG CARD */
  @keyframes fadeSlideUp {
    from { opacity: 0; transform: translateY(14px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  .bug-card {
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 14px;
    animation: fadeSlideUp 0.35s ease both;
    border: 1px solid transparent;
  }

  .bug-card.critical {
    background: rgba(255,77,109,0.07);
    border-color: rgba(255,77,109,0.2);
  }

  .bug-card.warning {
    background: rgba(255,209,102,0.06);
    border-color: rgba(255,209,102,0.2);
  }

  .bug-card.info {
    background: rgba(0,229,160,0.05);
    border-color: rgba(0,229,160,0.15);
  }

  .bug-label {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    padding: 3px 8px;
    border-radius: 4px;
    margin-bottom: 10px;
  }

  .bug-label.critical { color: ${THEMES.accent}; background: rgba(255,77,109,0.12); }
  .bug-label.warning  { color: ${THEMES.yellow}; background: rgba(255,209,102,0.1); }
  .bug-label.info     { color: ${THEMES.green}; background: rgba(0,229,160,0.1); }

  .bug-title {
    font-size: 14px;
    font-weight: 700;
    color: #fff;
    margin-bottom: 6px;
  }

  .bug-desc {
    font-size: 13px;
    color: #9898b0;
    line-height: 1.65;
    margin-bottom: 12px;
  }

  .fix-block {
    background: rgba(0,0,0,0.3);
    border-radius: 8px;
    padding: 12px 14px;
    border-left: 3px solid ${THEMES.green};
  }

  .fix-label {
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    color: ${THEMES.green};
    letter-spacing: 1px;
    font-weight: 700;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .fix-code {
    font-family: 'Space Mono', monospace;
    font-size: 12px;
    color: #c8ffe4;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
  }

  .fix-explanation {
    margin-top: 8px;
    font-size: 12.5px;
    color: #7a7a95;
    line-height: 1.6;
  }

  /* SUMMARY BAR */
  .summary-bar {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background: ${THEMES.surface};
    border-bottom: 1px solid ${THEMES.border};
    font-family: 'Space Mono', monospace;
    font-size: 11px;
  }

  .summary-pill {
    display: flex;
    align-items: center;
    gap: 5px;
    padding: 3px 9px;
    border-radius: 100px;
  }

  .summary-pill.critical { background: rgba(255,77,109,0.12); color: ${THEMES.accent}; }
  .summary-pill.warning  { background: rgba(255,209,102,0.1); color: ${THEMES.yellow}; }
  .summary-pill.info     { background: rgba(0,229,160,0.1); color: ${THEMES.green}; }

  .clean-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 280px;
    gap: 14px;
  }

  .clean-icon {
    font-size: 48px;
  }

  .clean-text {
    font-family: 'Space Mono', monospace;
    font-size: 13px;
    color: ${THEMES.green};
    text-align: center;
  }

  /* CLEAR BTN */
  .clear-btn {
    background: transparent;
    border: 1px solid ${THEMES.border};
    color: ${THEMES.muted};
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    padding: 4px 10px;
    border-radius: 6px;
    cursor: pointer;
    transition: all 0.15s;
    letter-spacing: 0.5px;
  }

  .clear-btn:hover {
    border-color: ${THEMES.accent};
    color: ${THEMES.accent};
  }

  /* EXAMPLE CHIPS */
  .example-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px 16px;
    border-top: 1px solid ${THEMES.border};
    flex-wrap: wrap;
  }

  .example-label {
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    color: ${THEMES.muted};
    letter-spacing: 0.5px;
    white-space: nowrap;
  }

  .chip {
    font-family: 'Space Mono', monospace;
    font-size: 10px;
    padding: 4px 10px;
    border-radius: 6px;
    background: ${THEMES.surface};
    border: 1px solid ${THEMES.border};
    color: #9898b0;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }

  .chip:hover {
    border-color: ${THEMES.accent};
    color: ${THEMES.accent};
    background: ${THEMES.accentSoft};
  }

  /* STREAM CURSOR */
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
  .stream-cursor {
    display: inline-block;
    width: 2px;
    height: 14px;
    background: ${THEMES.accent};
    margin-left: 2px;
    vertical-align: middle;
    animation: blink 0.8s step-end infinite;
  }

  .stream-text {
    font-size: 13px;
    color: #9898b0;
    line-height: 1.8;
    padding: 16px;
    font-family: 'Space Mono', monospace;
    white-space: pre-wrap;
  }
`;
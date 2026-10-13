/**
 * Plugin stylesheet, injected once as `<style data-plugin="dsh-security-plugin">`.
 * Every class is prefixed `dshsec-`. Colors come from DSH theme tokens
 * (`--dsw-alias-*`) with light fallbacks, so DSH's light and dark themes
 * apply automatically. Severity color is reserved for severity: critical and
 * high use the error tokens, medium the warn tokens, low and info stay neutral.
 */

export const STYLE_ATTRIBUTE = 'dsh-security-plugin'

const tokens = /* css */ `
.dshsec-root {
  --dshsec-bg: var(--dsw-alias-bg-base, #ffffff);
  --dshsec-l1: var(--dsw-alias-bg-layer-1, #f7f7f8);
  --dshsec-l2: var(--dsw-alias-bg-layer-2, #f0f0f2);
  --dshsec-l3: var(--dsw-alias-bg-layer-3, #e7e7ea);
  --dshsec-text: var(--dsw-alias-label-primary, #1f1f1f);
  --dshsec-text2: var(--dsw-alias-label-secondary, #4a4a4f);
  --dshsec-text3: var(--dsw-alias-label-tertiary, #76767c);
  --dshsec-caption: var(--dsw-alias-label-caption, #93939a);
  --dshsec-b1: var(--dsw-alias-border-l1, rgba(0, 0, 0, 0.07));
  --dshsec-b2: var(--dsw-alias-border-l2, rgba(0, 0, 0, 0.12));
  --dshsec-b3: var(--dsw-alias-border-l3, rgba(0, 0, 0, 0.2));
  --dshsec-brand: var(--dsw-alias-brand-primary, #4d6bfe);
  --dshsec-fill: var(--dsw-alias-button-primary-fill, #4d6bfe);
  --dshsec-fill-hover: var(--dsw-alias-button-primary-hover, #3c59e8);
  --dshsec-hover: var(--dsw-alias-interactive-bg-hover, rgba(0, 0, 0, 0.04));
  --dshsec-pressed: var(--dsw-alias-interactive-bg-active, rgba(0, 0, 0, 0.08));
  --dshsec-err: var(--dsw-alias-state-error-primary, #d1352b);
  --dshsec-err-bg: var(--dsw-alias-state-error-secondary, #fdeeec);
  --dshsec-warn: var(--dsw-alias-state-warn-primary, #c27400);
  --dshsec-warn-bg: var(--dsw-alias-state-warn-secondary, #fff5e3);
  --dshsec-warn-text: var(--dsw-alias-state-warn-label, #8a5300);
  --dshsec-ok: var(--dsw-alias-state-success-primary, #1f8a4c);
  --dshsec-ok-bg: var(--dsw-alias-state-success-secondary, #e8f5ed);
  --dshsec-link: var(--dsw-alias-link, #3d5cf5);
  --dshsec-code: var(--dsw-alias-markdown-code-block, #f5f6f8);
  --dshsec-card: var(--dsw-alias-settings-card-fill, var(--dshsec-l1));
  --dshsec-card-stroke: var(--dsw-alias-settings-card-stroke, var(--dshsec-b1));
  --dshsec-mono: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  color: var(--dshsec-text);
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
.dshsec-root *, .dshsec-root *::before, .dshsec-root *::after { box-sizing: border-box; }
.dshsec-root :focus-visible { outline: 2px solid var(--dshsec-brand); outline-offset: 2px; border-radius: 6px; }
.dshsec-root p { margin: 0; }
.dshsec-root h1, .dshsec-root h2, .dshsec-root h3, .dshsec-root h4 { margin: 0; }
.dshsec-visually-hidden {
  position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.dshsec-muted { color: var(--dshsec-text3); }
.dshsec-hint { color: var(--dshsec-text3); font-size: 12.5px; line-height: 1.55; }
.dshsec-num { font-variant-numeric: tabular-nums; }
.dshsec-mono, .dshsec-cell-mono { font-family: var(--dshsec-mono); font-size: 12.5px; }
.dshsec-link { color: var(--dshsec-link); text-decoration: none; overflow-wrap: anywhere; }
.dshsec-link:hover { text-decoration: underline; }
.dshsec-stack { display: grid; gap: 16px; }
.dshsec-stack-sm { display: grid; gap: 8px; }
.dshsec-stack-lg { display: grid; gap: 32px; }
.dshsec-h2 { font-size: 16px; line-height: 24px; font-weight: 500; }
.dshsec-h3 { font-size: 14px; line-height: 22px; font-weight: 500; }
.dshsec-h4 { font-size: 13px; line-height: 20px; font-weight: 500; color: var(--dshsec-text2); }
.dshsec-list { margin: 0; padding-left: 1.25em; display: grid; gap: 4px; }
.dshsec-list li::marker { color: var(--dshsec-caption); }
`

const frame = /* css */ `
.dshsec-page {
  width: 100%; height: 100%; min-height: 0; display: flex; flex-direction: column;
  background: var(--dshsec-bg);
}
.dshsec-scroll { flex: 1 1 auto; min-height: 0; overflow: auto; overscroll-behavior: contain; }
.dshsec-column {
  max-width: 960px; margin: 0 auto;
  padding: 0 clamp(24px, 4vw, 48px) 48px;
}
.dshsec-column--wide { max-width: 1320px; }
@media (max-width: 480px) { .dshsec-column { padding: 0 16px 32px; } }
.dshsec-head {
  padding-top: 28px; padding-bottom: 16px;
  display: flex; align-items: center; justify-content: space-between; gap: 12px 16px; flex-wrap: wrap;
}
[data-platform='darwin'] .dshsec-head { padding-top: calc(28px + var(--dsh-frame-top-clearance, 0px)); }
.dshsec-title { font-size: 20px; line-height: 28px; font-weight: 500; }
.dshsec-head-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; min-width: 0; }
.dshsec-workspace { max-width: min(360px, 100%); }
.dshsec-banners { display: grid; gap: 8px; }
.dshsec-banners:not(:empty) { margin-bottom: 12px; }
.dshsec-tabs {
  display: flex; gap: 4px; border-bottom: 1px solid var(--dshsec-b1);
  overflow-x: auto; scrollbar-width: none; margin-bottom: 24px;
}
.dshsec-tab {
  appearance: none; background: none; border: 0; cursor: pointer; font: inherit;
  color: var(--dshsec-text3); padding: 8px 12px 10px; position: relative; white-space: nowrap;
  border-radius: 6px 6px 0 0;
}
.dshsec-tab:hover { color: var(--dshsec-text); }
.dshsec-tab[aria-selected='true'] { color: var(--dshsec-text); font-weight: 500; }
.dshsec-tab[aria-selected='true']::after {
  content: ''; position: absolute; left: 12px; right: 12px; bottom: -1px; height: 2px;
  background: var(--dshsec-text); border-radius: 2px;
}
.dshsec-tabpanel:focus-visible { outline-offset: 6px; }
.dshsec-loading { display: flex; align-items: center; gap: 10px; color: var(--dshsec-text3); padding: 24px 0; }
.dshsec-spinner {
  width: 14px; height: 14px; border-radius: 50%; border: 2px solid var(--dshsec-b2);
  border-top-color: var(--dshsec-brand); animation: dshsec-spin 0.8s linear infinite; flex: none;
}
@keyframes dshsec-spin { to { transform: rotate(360deg); } }
.dshsec-empty { padding: 32px 0; display: grid; gap: 12px; max-width: 560px; }
.dshsec-empty-body { color: var(--dshsec-text2); }
`

const controls = /* css */ `
.dshsec-btn {
  appearance: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  height: 32px; padding: 0 14px; border-radius: 8px; border: 1px solid transparent;
  font: inherit; font-size: 14px; font-weight: 500; line-height: 1; cursor: pointer; white-space: nowrap;
  transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease;
}
.dshsec-btn--sm { height: 28px; padding: 0 10px; font-size: 13px; border-radius: 7px; }
.dshsec-btn-icon { display: inline-flex; }
.dshsec-btn--primary { background: var(--dshsec-fill); color: #fff; }
.dshsec-btn--primary:hover:not(:disabled) { background: var(--dshsec-fill-hover); }
.dshsec-btn--secondary { background: var(--dshsec-bg); border-color: var(--dshsec-b2); color: var(--dshsec-text); }
.dshsec-btn--secondary:hover:not(:disabled) { background: var(--dshsec-hover); }
.dshsec-btn--ghost { background: transparent; color: var(--dshsec-text2); }
.dshsec-btn--ghost:hover:not(:disabled) { background: var(--dshsec-hover); color: var(--dshsec-text); }
.dshsec-btn--danger { background: var(--dshsec-err); color: #fff; }
.dshsec-btn--danger:hover:not(:disabled) { filter: brightness(0.94); }
.dshsec-btn--link {
  background: none; border: 0; padding: 0 2px; height: auto; color: var(--dshsec-link); font-weight: 500;
}
.dshsec-btn--link:hover:not(:disabled) { text-decoration: underline; }
.dshsec-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.dshsec-btn[aria-busy='true'] { cursor: progress; opacity: 0.75; }
.dshsec-btn[aria-busy='true']::before {
  content: ''; width: 12px; height: 12px; border-radius: 50%; border: 2px solid currentColor;
  border-right-color: transparent; animation: dshsec-spin 0.8s linear infinite;
}
.dshsec-btn[aria-busy='true'] .dshsec-btn-icon { display: none; }
.dshsec-btn-group { display: flex; gap: 6px; flex-wrap: wrap; }
.dshsec-iconbtn {
  appearance: none; border: 0; background: none; color: var(--dshsec-text3); cursor: pointer;
  width: 32px; height: 32px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
}
.dshsec-iconbtn:hover { background: var(--dshsec-hover); color: var(--dshsec-text); }
.dshsec-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

.dshsec-field { display: grid; gap: 6px; min-width: 0; align-content: start; }
.dshsec-label { font-size: 13px; font-weight: 500; color: var(--dshsec-text); line-height: 20px; }
.dshsec-field-error { color: var(--dshsec-err); font-size: 12.5px; }
.dshsec-input, .dshsec-textarea, .dshsec-select select, .dshsec-search input {
  font: inherit; font-size: 14px; color: var(--dshsec-text); background: var(--dshsec-bg);
  border: 1px solid var(--dshsec-b2); border-radius: 8px; width: 100%; min-width: 0;
}
.dshsec-input { height: 32px; padding: 0 10px; }
.dshsec-input--num { font-variant-numeric: tabular-nums; max-width: 220px; }
.dshsec-textarea { padding: 8px 10px; resize: vertical; line-height: 1.5; min-height: 64px; }
.dshsec-input:focus, .dshsec-textarea:focus, .dshsec-select select:focus, .dshsec-search input:focus {
  outline: 2px solid var(--dshsec-brand); outline-offset: 1px; border-color: transparent;
}
.dshsec-input[aria-invalid='true'], .dshsec-select select[aria-invalid='true'] { border-color: var(--dshsec-err); }
.dshsec-select { position: relative; display: inline-flex; min-width: 0; max-width: 100%; }
.dshsec-field .dshsec-select { display: flex; }
.dshsec-select select {
  appearance: none; height: 32px; padding: 0 30px 0 10px; cursor: pointer;
  text-overflow: ellipsis; white-space: nowrap; overflow: hidden;
}
.dshsec-select select:disabled { opacity: 0.55; cursor: not-allowed; }
.dshsec-select::after {
  content: ''; position: absolute; right: 12px; top: 50%; width: 6px; height: 6px; pointer-events: none;
  border-right: 1.5px solid var(--dshsec-text3); border-bottom: 1.5px solid var(--dshsec-text3);
  transform: translateY(-70%) rotate(45deg);
}
.dshsec-select option { color: initial; }
.dshsec-check { display: flex; gap: 10px; align-items: flex-start; cursor: pointer; line-height: 1.5; }
.dshsec-check input { margin: 3px 0 0; width: 16px; height: 16px; accent-color: var(--dshsec-fill); flex: none; }
.dshsec-fieldset { border: 0; margin: 0; padding: 0; min-width: 0; display: grid; gap: 10px; }
.dshsec-fieldset > legend { padding: 0; margin-bottom: 10px; }

.dshsec-toggle-row { display: flex; gap: 16px; align-items: flex-start; justify-content: space-between; }
.dshsec-toggle-text { display: grid; gap: 2px; min-width: 0; }
.dshsec-toggle-note { font-size: 12.5px; color: var(--dshsec-warn-text); }
.dshsec-switch {
  appearance: none; flex: none; position: relative; width: 36px; height: 20px; margin-top: 1px;
  border-radius: 10px; border: 0; background: var(--dshsec-b3); cursor: pointer; transition: background-color 140ms ease;
}
.dshsec-switch-thumb {
  position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
  background: #fff; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.25); transition: transform 140ms ease;
}
.dshsec-switch[aria-checked='true'] { background: var(--dshsec-fill); }
.dshsec-switch[aria-checked='true'] .dshsec-switch-thumb { transform: translateX(16px); }
.dshsec-switch:disabled { opacity: 0.45; cursor: not-allowed; }
.dshsec-switch:focus-visible { border-radius: 10px; }

.dshsec-callout {
  display: flex; gap: 10px; align-items: flex-start; padding: 10px 14px; border-radius: 8px;
  background: var(--dshsec-l1); color: var(--dshsec-text);
}
.dshsec-callout-icon { flex: none; display: inline-flex; margin-top: 3px; color: var(--dshsec-text3); }
.dshsec-callout-main { flex: 1 1 auto; min-width: 0; display: grid; gap: 2px; }
.dshsec-callout-title { font-weight: 500; }
.dshsec-callout-body { color: var(--dshsec-text2); overflow-wrap: anywhere; }
.dshsec-callout-action { flex: none; align-self: center; }
.dshsec-callout--success { background: var(--dshsec-ok-bg); }
.dshsec-callout--success .dshsec-callout-icon { color: var(--dshsec-ok); }
.dshsec-callout--warn { background: var(--dshsec-warn-bg); }
.dshsec-callout--warn .dshsec-callout-icon { color: var(--dshsec-warn); }
.dshsec-callout--warn .dshsec-callout-body { color: var(--dshsec-warn-text); }
.dshsec-callout--error { background: var(--dshsec-err-bg); }
.dshsec-callout--error .dshsec-callout-icon { color: var(--dshsec-err); }
@media (max-width: 520px) {
  .dshsec-callout { flex-wrap: wrap; }
  .dshsec-callout-action { flex-basis: 100%; padding-left: 26px; }
}

.dshsec-badge {
  display: inline-flex; align-items: center; height: 20px; padding: 0 7px; border-radius: 6px;
  font-size: 12px; font-weight: 500; line-height: 1; white-space: nowrap;
  background: var(--dshsec-l2); color: var(--dshsec-text2);
}
.dshsec-badge--quiet { background: transparent; box-shadow: inset 0 0 0 1px var(--dshsec-b2); color: var(--dshsec-text3); }
.dshsec-badge--brand { color: var(--dshsec-brand); background: color-mix(in srgb, var(--dshsec-brand) 12%, transparent); }
.dshsec-badge--success { background: var(--dshsec-ok-bg); color: var(--dshsec-ok); }
.dshsec-badge--warn { background: var(--dshsec-warn-bg); color: var(--dshsec-warn-text); }
.dshsec-badge--error { background: var(--dshsec-err-bg); color: var(--dshsec-err); }
.dshsec-badge--error-strong { background: var(--dshsec-err); color: #fff; }

/* Certainty glyph: three ascending bars filled to how firmly a finding is established. */
.dshsec-certainty { display: inline-flex; align-items: flex-end; gap: 2px; height: 12px; flex: none; }
.dshsec-certainty > span { width: 3px; border-radius: 1px; background: var(--dshsec-b3); }
.dshsec-certainty > span:nth-child(1) { height: 5px; }
.dshsec-certainty > span:nth-child(2) { height: 8.5px; }
.dshsec-certainty > span:nth-child(3) { height: 12px; }
.dshsec-certainty--1 > span:nth-child(-n + 1),
.dshsec-certainty--2 > span:nth-child(-n + 2),
.dshsec-certainty--3 > span { background: currentColor; }
.dshsec-verif { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--dshsec-text2); white-space: nowrap; }
.dshsec-verif--strong_static_evidence, .dshsec-verif--proven_dynamic { color: var(--dshsec-text); font-weight: 500; }
.dshsec-verif--refuted { color: var(--dshsec-caption); }

.dshsec-menu-wrap { position: relative; display: inline-flex; }
.dshsec-menu {
  position: absolute; top: calc(100% + 4px); z-index: 20; min-width: 160px; padding: 4px;
  background: var(--dshsec-bg); border: 1px solid var(--dshsec-b2); border-radius: 10px;
  box-shadow: 0 10px 28px rgba(0, 0, 0, 0.14); display: grid;
}
.dshsec-menu--end { right: 0; }
.dshsec-menu--start { left: 0; }
.dshsec-menu-item {
  appearance: none; border: 0; background: none; font: inherit; color: var(--dshsec-text); text-align: left;
  padding: 7px 10px; border-radius: 6px; cursor: pointer;
}
.dshsec-menu-item:hover, .dshsec-menu-item:focus-visible { background: var(--dshsec-hover); outline-offset: -2px; }

.dshsec-table-wrap { overflow-x: auto; }
.dshsec-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.dshsec-table th {
  text-align: left; font-weight: 500; color: var(--dshsec-text3); font-size: 12px;
  padding: 6px 12px 6px 0; border-bottom: 1px solid var(--dshsec-b2); white-space: nowrap;
}
.dshsec-table td { padding: 9px 12px 9px 0; border-bottom: 1px solid var(--dshsec-b1); vertical-align: middle; }
.dshsec-table .dshsec-num { text-align: right; }
.dshsec-cell-wrap { min-width: 160px; }
`

const modal = /* css */ `
.dshsec-modal-backdrop {
  position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center;
  padding: 16px; background: rgba(0, 0, 0, 0.36);
}
.dshsec-modal {
  width: 100%; max-height: calc(100vh - 32px); display: flex; flex-direction: column;
  background: var(--dshsec-bg); color: var(--dshsec-text); border-radius: 12px;
  border: 1px solid var(--dshsec-b1); box-shadow: 0 24px 64px rgba(0, 0, 0, 0.22);
}
.dshsec-modal:focus { outline: none; }
.dshsec-modal--sm { max-width: 440px; }
.dshsec-modal--md { max-width: 560px; }
.dshsec-modal--lg { max-width: 720px; }
.dshsec-modal-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 18px 20px 10px 24px; }
.dshsec-modal-title { font-size: 16px; line-height: 24px; font-weight: 500; }
.dshsec-modal-body { padding: 4px 24px 20px; overflow: auto; display: grid; gap: 16px; }
.dshsec-modal-foot {
  display: flex; justify-content: flex-end; gap: 8px; flex-wrap: wrap;
  padding: 14px 24px 18px; border-top: 1px solid var(--dshsec-b1);
}
@media (max-width: 480px) {
  .dshsec-modal-backdrop { padding: 8px; align-items: flex-end; }
  .dshsec-modal-head { padding: 14px 12px 8px 16px; }
  .dshsec-modal-body { padding: 4px 16px 16px; }
  .dshsec-modal-foot { padding: 12px 16px 14px; }
  .dshsec-modal-foot .dshsec-btn { flex: 1 1 auto; }
}
.dshsec-subsection { display: grid; gap: 10px; }
.dshsec-subhead { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; }
.dshsec-kv { margin: 0; display: grid; gap: 6px; }
.dshsec-kv-row { display: grid; grid-template-columns: minmax(120px, 200px) 1fr; gap: 12px; align-items: baseline; }
.dshsec-kv-row dt { color: var(--dshsec-text3); font-size: 13px; }
.dshsec-kv-row dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.dshsec-kv-row dd .dshsec-meter { margin-top: 6px; }
.dshsec-kv--compact .dshsec-kv-row { grid-template-columns: minmax(110px, 170px) 1fr; }
@media (max-width: 520px) { .dshsec-kv-row, .dshsec-kv--compact .dshsec-kv-row { grid-template-columns: 1fr; gap: 0; } }
.dshsec-estimate {
  margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
  border: 1px solid var(--dshsec-b1); border-radius: 10px; overflow: hidden;
}
.dshsec-estimate > div { padding: 10px 14px; border-right: 1px solid var(--dshsec-b1); }
.dshsec-estimate > div:last-child { border-right: 0; }
.dshsec-estimate dt { font-size: 12px; color: var(--dshsec-text3); }
.dshsec-estimate dd { margin: 0; font-size: 18px; line-height: 26px; font-variant-numeric: tabular-nums; }
.dshsec-modes { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
@media (max-width: 640px) { .dshsec-modes { grid-template-columns: 1fr; } }
.dshsec-mode {
  position: relative; display: grid; gap: 4px; align-content: start; padding: 12px 14px; cursor: pointer;
  border: 1px solid var(--dshsec-b2); border-radius: 10px; background: var(--dshsec-bg);
  transition: border-color 120ms ease, background-color 120ms ease;
}
.dshsec-mode:hover { background: var(--dshsec-hover); }
.dshsec-mode input { position: absolute; opacity: 0; pointer-events: none; }
.dshsec-mode.is-selected { border-color: var(--dshsec-brand); box-shadow: inset 0 0 0 1px var(--dshsec-brand); }
.dshsec-mode:has(input:focus-visible) { outline: 2px solid var(--dshsec-brand); outline-offset: 2px; }
.dshsec-mode-name { font-weight: 500; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dshsec-mode-rec { font-size: 11.5px; font-weight: 500; color: var(--dshsec-brand); }
.dshsec-mode-desc { font-size: 12.5px; color: var(--dshsec-text3); line-height: 1.5; }
.dshsec-consent {
  display: grid; gap: 10px; padding: 16px; border-radius: 10px;
  background: var(--dshsec-l1); border: 1px solid var(--dshsec-b1);
}
`

const overview = /* css */ `
.dshsec-intro { display: grid; gap: 20px; max-width: 720px; padding-top: 8px; }
.dshsec-intro-title { font-size: 18px; line-height: 26px; font-weight: 500; }
.dshsec-intro-body { color: var(--dshsec-text2); max-width: 64ch; }
.dshsec-leaves {
  display: grid; gap: 8px; padding: 14px 18px; border-left: 2px solid var(--dshsec-b3);
  background: var(--dshsec-l1); border-radius: 0 10px 10px 0;
}
.dshsec-leaves .dshsec-list { color: var(--dshsec-text2); }

.dshsec-card {
  display: grid; gap: 20px; padding: 20px 24px; border-radius: 12px;
  background: var(--dshsec-card); border: 1px solid var(--dshsec-card-stroke);
}
@media (max-width: 480px) { .dshsec-card { padding: 16px; } }
.dshsec-card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px 16px; flex-wrap: wrap; }
.dshsec-card-sub { display: flex; align-items: center; gap: 2px 14px; flex-wrap: wrap; font-size: 13px; margin-top: 2px; }
.dshsec-card-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.dshsec-problem--failed { border-color: color-mix(in srgb, var(--dshsec-err) 35%, transparent); }
.dshsec-problem--interrupted { border-color: color-mix(in srgb, var(--dshsec-warn) 35%, transparent); }

.dshsec-steps { list-style: none; margin: 0; padding: 0; display: flex; flex-wrap: wrap; gap: 6px 2px; }
.dshsec-step { display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; color: var(--dshsec-caption); }
.dshsec-step:not(:last-child)::after {
  content: ''; width: 14px; height: 1px; background: var(--dshsec-b2); margin: 0 4px 0 2px;
}
.dshsec-step-dot { width: 8px; height: 8px; border-radius: 50%; border: 1.5px solid var(--dshsec-b3); flex: none; }
.dshsec-step--done { color: var(--dshsec-text3); }
.dshsec-step--done .dshsec-step-dot { background: var(--dshsec-text3); border-color: var(--dshsec-text3); }
.dshsec-step--skipped .dshsec-step-dot { border-style: dashed; }
.dshsec-step--skipped .dshsec-step-label { text-decoration: line-through; text-decoration-color: var(--dshsec-b3); }
.dshsec-step--running { color: var(--dshsec-text); font-weight: 500; }
.dshsec-step--running .dshsec-step-dot {
  background: var(--dshsec-brand); border-color: var(--dshsec-brand);
  box-shadow: 0 0 0 0 color-mix(in srgb, var(--dshsec-brand) 45%, transparent);
  animation: dshsec-pulse 1.6s ease-out infinite;
}
@keyframes dshsec-pulse {
  0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--dshsec-brand) 45%, transparent); }
  100% { box-shadow: 0 0 0 6px transparent; }
}
.dshsec-live-line { display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.dshsec-meter { height: 4px; border-radius: 2px; background: var(--dshsec-l3); overflow: hidden; }
.dshsec-meter > span { display: block; height: 100%; border-radius: inherit; background: var(--dshsec-text3); transition: width 300ms ease; }
.dshsec-meter--strong { height: 6px; border-radius: 3px; }
.dshsec-meter--strong > span { background: var(--dshsec-brand); }
.dshsec-meter--warn > span { background: var(--dshsec-warn); }
.dshsec-usage { margin: 0; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
@media (max-width: 560px) { .dshsec-usage { grid-template-columns: 1fr; } }
.dshsec-usage-row { display: grid; gap: 4px; }
.dshsec-usage-row dt { font-size: 12px; color: var(--dshsec-text3); }
.dshsec-usage-row dd { margin: 0; display: grid; gap: 6px; }
.dshsec-wstate { font-size: 12.5px; color: var(--dshsec-text3); }
.dshsec-wstate--running { color: var(--dshsec-brand); }
.dshsec-wstate--failed { color: var(--dshsec-err); }
.dshsec-feed {
  list-style: none; margin: 0; padding: 8px 12px; max-height: 240px; overflow: auto;
  background: var(--dshsec-code); border-radius: 8px; font-size: 12.5px; line-height: 1.55;
  display: grid; gap: 2px; align-content: start;
}
.dshsec-feed-item { display: grid; grid-template-columns: auto 1fr; gap: 10px; }
.dshsec-feed-time { font-family: var(--dshsec-mono); font-size: 11.5px; color: var(--dshsec-caption); font-variant-numeric: tabular-nums; }
.dshsec-feed-msg { overflow-wrap: anywhere; color: var(--dshsec-text2); }
.dshsec-feed-item--debug .dshsec-feed-msg { color: var(--dshsec-caption); }
.dshsec-feed-item--warn .dshsec-feed-msg { color: var(--dshsec-warn-text); }
.dshsec-feed-item--error .dshsec-feed-msg { color: var(--dshsec-err); }

.dshsec-results { display: grid; gap: 28px; }
.dshsec-results-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px 16px; flex-wrap: wrap; }
.dshsec-export { display: grid; gap: 8px; justify-items: end; }
@media (max-width: 640px) { .dshsec-export { justify-items: start; } }
.dshsec-notsafe {
  display: grid; gap: 2px; padding: 12px 16px; border-left: 3px solid var(--dshsec-warn);
  background: var(--dshsec-l1); border-radius: 0 10px 10px 0;
}
.dshsec-notsafe span { color: var(--dshsec-text2); }
.dshsec-notsafe--prominent { background: var(--dshsec-warn-bg); }
.dshsec-notsafe--prominent span { color: var(--dshsec-warn-text); }

/* Severity ledger: one strip, not five cards. Color only where there is something to see. */
.dshsec-ledger {
  list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: repeat(5, minmax(0, 1fr));
  border: 1px solid var(--dshsec-b2); border-radius: 12px; overflow: hidden;
}
.dshsec-ledger > li + li { border-left: 1px solid var(--dshsec-b1); }
.dshsec-ledger-cell {
  appearance: none; border: 0; background: none; font: inherit; color: inherit; cursor: pointer;
  width: 100%; height: 100%; padding: 14px 16px 12px; display: grid; gap: 2px; text-align: left;
}
.dshsec-ledger-cell:hover { background: var(--dshsec-hover); }
.dshsec-ledger-cell:focus-visible { outline-offset: -2px; border-radius: 0; }
.dshsec-ledger-num { font-size: 28px; line-height: 34px; font-weight: 500; font-variant-numeric: tabular-nums; color: var(--dshsec-caption); }
.dshsec-ledger-label { font-size: 12.5px; color: var(--dshsec-text3); }
.dshsec-ledger-cell.has-value .dshsec-ledger-num { color: var(--dshsec-text); }
.dshsec-ledger-cell--error-strong.has-value .dshsec-ledger-num,
.dshsec-ledger-cell--error.has-value .dshsec-ledger-num { color: var(--dshsec-err); }
.dshsec-ledger-cell--warn.has-value .dshsec-ledger-num { color: var(--dshsec-warn); }
.dshsec-ledger-cell--error-strong.has-value { box-shadow: inset 0 3px 0 var(--dshsec-err); }
@media (max-width: 560px) {
  .dshsec-ledger-cell { padding: 10px 8px 9px; }
  .dshsec-ledger-num { font-size: 20px; line-height: 26px; }
  .dshsec-ledger-label { font-size: 11.5px; overflow-wrap: anywhere; }
}
.dshsec-certainty-row { margin: 0; display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 16px; }
@media (max-width: 720px) { .dshsec-certainty-row { grid-template-columns: repeat(2, minmax(0, 1fr)); } }
.dshsec-cert { display: grid; gap: 2px; align-content: start; padding-top: 10px; border-top: 2px solid var(--dshsec-b1); }
.dshsec-cert dt { font-size: 13px; font-weight: 500; }
.dshsec-cert dd { margin: 0; display: grid; gap: 2px; }
.dshsec-cert-num { font-size: 22px; line-height: 28px; font-variant-numeric: tabular-nums; }
.dshsec-cert--confirmed { border-top-color: var(--dshsec-text); }
.dshsec-cert--open_proof_gap { border-top-color: var(--dshsec-b3); }
.dshsec-cert--ruled_out .dshsec-cert-num { color: var(--dshsec-text3); }
.dshsec-cert--new { border-top-color: var(--dshsec-brand); }
.dshsec-coverage .dshsec-kv { gap: 12px; }
.dshsec-viewing { margin-bottom: 4px; }
`

const findings = /* css */ `
.dshsec-findings { display: grid; gap: 16px; }
.dshsec-findings.is-split { grid-template-columns: minmax(340px, 420px) minmax(0, 1fr); gap: 32px; align-items: start; }
.dshsec-findings-list { display: grid; gap: 14px; min-width: 0; align-content: start; }
.dshsec-findings.is-split .dshsec-findings-detail {
  position: sticky; top: 16px; max-height: calc(100vh - 140px); overflow: auto;
  padding: 4px 4px 24px 24px; border-left: 1px solid var(--dshsec-b1);
}
.dshsec-findings-detail { min-width: 0; display: grid; gap: 12px; align-content: start; }
.dshsec-findings-detail--empty { align-content: center; min-height: 200px; }
.dshsec-back { justify-self: start; }

.dshsec-filters { display: grid; gap: 10px; }
.dshsec-search { position: relative; display: flex; align-items: center; }
.dshsec-search svg { position: absolute; left: 10px; color: var(--dshsec-caption); pointer-events: none; }
.dshsec-search input { height: 34px; padding: 0 10px 0 32px; }
.dshsec-chipgroup { display: grid; grid-template-columns: 96px 1fr; gap: 8px; align-items: center; }
@media (max-width: 480px) { .dshsec-chipgroup { grid-template-columns: 1fr; gap: 4px; } }
.dshsec-chipgroup-label { font-size: 12px; color: var(--dshsec-text3); }
.dshsec-chips { display: flex; flex-wrap: wrap; gap: 6px; }
.dshsec-chip {
  appearance: none; font: inherit; font-size: 12.5px; height: 26px; padding: 0 10px; border-radius: 13px;
  border: 1px solid var(--dshsec-b2); background: transparent; color: var(--dshsec-text3); cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px;
}
.dshsec-chip:hover { background: var(--dshsec-hover); }
.dshsec-chip[aria-pressed='true'] { background: var(--dshsec-l2); border-color: var(--dshsec-b3); color: var(--dshsec-text); }
.dshsec-chip--critical::before, .dshsec-chip--high::before, .dshsec-chip--medium::before,
.dshsec-chip--low::before, .dshsec-chip--info::before {
  content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--dshsec-b3);
}
.dshsec-chip--critical[aria-pressed='true']::before, .dshsec-chip--high[aria-pressed='true']::before { background: var(--dshsec-err); }
.dshsec-chip--medium[aria-pressed='true']::before { background: var(--dshsec-warn); }
.dshsec-chip--low[aria-pressed='true']::before, .dshsec-chip--info[aria-pressed='true']::before { background: var(--dshsec-text3); }
.dshsec-filters-foot { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }
.dshsec-count { font-size: 12.5px; }

.dshsec-flist { list-style: none; margin: 0; padding: 0; display: grid; border-top: 1px solid var(--dshsec-b1); }
.dshsec-flist > li, .dshsec-flist > .dshsec-frow { border-bottom: 1px solid var(--dshsec-b1); }
.dshsec-frow {
  appearance: none; border: 0; background: none; font: inherit; color: inherit; text-align: left; cursor: pointer;
  width: 100%; display: grid; grid-template-columns: 76px minmax(0, 1fr); gap: 12px; align-items: start;
  padding: 11px 10px; border-radius: 0;
}
.dshsec-flist > .dshsec-frow { border-bottom: 1px solid var(--dshsec-b1); }
.dshsec-frow:hover { background: var(--dshsec-hover); }
.dshsec-frow:focus-visible { outline-offset: -2px; border-radius: 6px; }
.dshsec-frow.is-selected { background: var(--dshsec-l2); box-shadow: inset 2px 0 0 var(--dshsec-text); }
.dshsec-frow.is-ruled-out .dshsec-frow-title { color: var(--dshsec-text3); }
.dshsec-frow-sev { padding-top: 1px; }
@media (max-width: 480px) { .dshsec-frow { grid-template-columns: 60px minmax(0, 1fr); gap: 10px; padding: 11px 4px; } }
.dshsec-frow-main { display: grid; gap: 4px; min-width: 0; }
.dshsec-frow-title { font-weight: 500; line-height: 1.45; overflow-wrap: anywhere; }
.dshsec-frow-meta { display: flex; align-items: center; gap: 6px 10px; flex-wrap: wrap; font-size: 12.5px; }
.dshsec-frow-loc { font-family: var(--dshsec-mono); font-size: 12px; color: var(--dshsec-text3); overflow-wrap: anywhere; min-width: 0; }

.dshsec-detail { display: grid; gap: 0; max-width: 820px; }
.dshsec-detail-head { display: grid; gap: 6px; padding-bottom: 16px; }
.dshsec-detail-tags { display: flex; gap: 6px; flex-wrap: wrap; }
.dshsec-detail-title { font-size: 18px; line-height: 26px; font-weight: 500; overflow-wrap: anywhere; }
.dshsec-detail-title:focus { outline: none; }
.dshsec-detail-loc { font-family: var(--dshsec-mono); font-size: 12.5px; color: var(--dshsec-text3); overflow-wrap: anywhere; }
.dshsec-dsec { display: grid; gap: 10px; padding: 18px 0; border-top: 1px solid var(--dshsec-b1); }
.dshsec-dsec-title { font-size: 15px; line-height: 22px; font-weight: 500; }
.dshsec-dsec-body { display: grid; gap: 12px; color: var(--dshsec-text); }
.dshsec-dsec-body > p, .dshsec-review p { max-width: 72ch; }
.dshsec-sure { display: grid; gap: 6px; padding: 12px 14px; border-radius: 10px; background: var(--dshsec-l1); }
.dshsec-sure .dshsec-verif { font-size: 14px; }
.dshsec-sure p { color: var(--dshsec-text2); }
.dshsec-review { display: grid; gap: 6px; }
.dshsec-review-verdict { font-size: 13.5px; }
.dshsec-path { list-style: none; margin: 0; padding: 0 0 0 14px; display: grid; gap: 14px; border-left: 2px solid var(--dshsec-b2); }
.dshsec-path-step { display: grid; gap: 8px; min-width: 0; }
.dshsec-path-step.is-unverified, .dshsec-evidence li.is-unverified {
  padding: 8px 10px; margin-left: -10px; border-radius: 8px; background: var(--dshsec-warn-bg);
}
.dshsec-path-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dshsec-path-n { font-size: 12.5px; font-weight: 500; color: var(--dshsec-text3); }
.dshsec-evidence { list-style: none; margin: 0; padding: 0; display: grid; gap: 14px; }
.dshsec-evidence li { display: grid; gap: 8px; min-width: 0; }
.dshsec-code { margin: 0; border-radius: 8px; overflow: hidden; border: 1px solid var(--dshsec-b1); background: var(--dshsec-code); min-width: 0; }
.dshsec-code-path {
  font-family: var(--dshsec-mono); font-size: 11.5px; color: var(--dshsec-text3);
  padding: 5px 12px; border-bottom: 1px solid var(--dshsec-b1); overflow-wrap: anywhere;
}
.dshsec-code pre {
  margin: 0; padding: 8px 0; overflow-x: auto; font-family: var(--dshsec-mono); font-size: 12.5px; line-height: 1.6;
  tab-size: 2;
}
.dshsec-code pre:focus-visible { outline-offset: -2px; }
.dshsec-code code { display: block; min-width: max-content; }
.dshsec-code-line { display: block; padding-right: 16px; white-space: pre; }
.dshsec-code-ln {
  display: inline-block; padding: 0 10px 0 12px; margin-right: 12px; color: var(--dshsec-caption);
  border-right: 1px solid var(--dshsec-b1); user-select: none; text-align: right; white-space: pre;
}
.dshsec-triage { display: grid; gap: 12px; padding: 18px 16px; margin-top: 4px; border-radius: 12px; background: var(--dshsec-l1); }
.dshsec-segmented { display: flex; flex-wrap: wrap; gap: 6px; }
.dshsec-seg {
  position: relative; display: inline-flex; align-items: center; height: 30px; padding: 0 12px; border-radius: 8px;
  border: 1px solid var(--dshsec-b2); background: var(--dshsec-bg); cursor: pointer; font-size: 13px;
}
.dshsec-seg input { position: absolute; opacity: 0; pointer-events: none; }
.dshsec-seg.is-selected { border-color: var(--dshsec-text); box-shadow: inset 0 0 0 1px var(--dshsec-text); font-weight: 500; }
.dshsec-seg:has(input:focus-visible) { outline: 2px solid var(--dshsec-brand); outline-offset: 2px; }
.dshsec-refs { display: grid; gap: 10px; padding-top: 20px; margin-top: 8px; }
.dshsec-refs-list { font-size: 13px; }

.dshsec-history .dshsec-table td { vertical-align: middle; }
.dshsec-history tr.is-viewing td { background: var(--dshsec-l1); }
.dshsec-row-actions { display: flex; gap: 6px; justify-content: flex-end; flex-wrap: wrap; padding-right: 0 !important; }
.dshsec-counts { display: inline-flex; gap: 4px; flex-wrap: wrap; }
.dshsec-count-pill {
  display: inline-flex; gap: 4px; align-items: center; height: 20px; padding: 0 6px; border-radius: 5px;
  font-size: 12px; font-variant-numeric: tabular-nums; background: var(--dshsec-l2); color: var(--dshsec-text2);
}
.dshsec-count-pill--error-strong, .dshsec-count-pill--error { background: var(--dshsec-err-bg); color: var(--dshsec-err); }
.dshsec-count-pill--warn { background: var(--dshsec-warn-bg); color: var(--dshsec-warn-text); }
.dshsec-dirty { color: var(--dshsec-warn); margin-left: 2px; }
@media (max-width: 680px) {
  .dshsec-history thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  .dshsec-history tr { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; padding: 12px 0; border-bottom: 1px solid var(--dshsec-b1); }
  .dshsec-history td { border: 0; padding: 0; display: block; }
  .dshsec-history td[data-label]::before { content: attr(data-label); display: block; font-size: 11.5px; color: var(--dshsec-text3); }
  .dshsec-history .dshsec-row-actions { grid-column: 1 / -1; justify-content: flex-start; padding-top: 4px; display: flex; }
}
`

const settings = /* css */ `
.dshsec-settings-host { display: grid; gap: 16px; }
.dshsec-settings-intro { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.dshsec-settings { display: grid; gap: 0; container-type: inline-size; }
.dshsec-sgroup { display: grid; gap: 14px; padding: 24px 0; border-top: 1px solid var(--dshsec-b1); }
.dshsec-sgroup:first-child { border-top: 0; padding-top: 0; }
.dshsec-sgroup-head { display: grid; gap: 4px; align-content: start; }
.dshsec-sgroup-title { font-size: 15px; line-height: 22px; font-weight: 500; }
.dshsec-sgroup-head .dshsec-muted { font-size: 13px; }
.dshsec-sgroup-body { display: grid; gap: 18px; min-width: 0; }
@container (min-width: 760px) {
  .dshsec-sgroup { grid-template-columns: 200px minmax(0, 1fr); gap: 32px; }
}
.dshsec-grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; }
.dshsec-roles { display: grid; gap: 0; }
.dshsec-role { border: 0; margin: 0; padding: 14px 0; border-bottom: 1px solid var(--dshsec-b1); min-width: 0; display: grid; gap: 8px; }
.dshsec-role:first-child { padding-top: 0; }
.dshsec-role:last-child { border-bottom: 0; }
.dshsec-role > legend { padding: 0; float: left; width: 100%; }
.dshsec-role > legend + * { clear: both; }
.dshsec-role-name { font-weight: 500; font-size: 14px; }
.dshsec-role-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
.dshsec-budgets { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 20px; }
.dshsec-budget { border: 0; margin: 0; padding: 0; display: grid; gap: 10px; min-width: 0; align-content: start; }
.dshsec-budget > legend { padding: 0; margin-bottom: 6px; }
.dshsec-budget .dshsec-input--num { max-width: none; }
.dshsec-analyzers { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.dshsec-analyzers li { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.dshsec-analyzer-name { font-weight: 500; }
.dshsec-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; align-self: center; }
.dshsec-dot.is-on { background: var(--dshsec-ok); }
.dshsec-dot.is-off { background: var(--dshsec-b3); }
.dshsec-tools { list-style: none; margin: 0; padding: 0; display: grid; gap: 0; }
.dshsec-tool { display: grid; gap: 6px; padding: 12px 0; border-bottom: 1px solid var(--dshsec-b1); }
.dshsec-tool:last-child { border-bottom: 0; }
.dshsec-tool-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dshsec-tool-meta { display: flex; gap: 4px 14px; flex-wrap: wrap; font-size: 12.5px; }
.dshsec-tool-install { display: grid; gap: 8px; padding: 10px 12px; border-radius: 8px; background: var(--dshsec-l1); }
.dshsec-install-hint { white-space: pre-wrap; overflow-wrap: anywhere; }
.dshsec-savebar {
  position: sticky; bottom: 0; z-index: 5; display: flex; align-items: center; justify-content: space-between;
  gap: 12px; flex-wrap: wrap; padding: 12px 0; margin-top: 8px;
  background: var(--dshsec-bg); border-top: 1px solid var(--dshsec-b2);
  box-shadow: 0 -10px 18px -14px rgba(0, 0, 0, 0.25);
}
.dshsec-savebar-text { color: var(--dshsec-text2); font-size: 13px; }
.dshsec-savebar-actions { display: flex; gap: 8px; margin-left: auto; }
`

const motion = /* css */ `
@media (prefers-reduced-motion: reduce) {
  .dshsec-root *, .dshsec-root *::before, .dshsec-root *::after {
    animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important;
  }
  .dshsec-spinner, .dshsec-btn[aria-busy='true']::before { animation: none !important; }
}
`

export const STYLES = [tokens, frame, controls, modal, overview, findings, settings, motion].join('\n')

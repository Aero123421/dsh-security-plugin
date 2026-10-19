/**
 * Plugin stylesheet, injected once as `<style data-plugin="dsh-security-plugin">`.
 * Every class is prefixed `dshsec-`. Colors come from DSH theme tokens
 * (`--dsw-alias-*`) with light fallbacks, so DSH's light and dark themes
 * apply automatically.
 *
 * Token notes (DSH 0.2.x): `bg-layer-*` are all white in the light theme and
 * the `state-*-secondary` tokens are saturated colors, not tints. Surfaces
 * therefore use the alpha-based `interactive-bg-*` fills, tints use the
 * `*-tertiary` tokens or `color-mix`, and text on colored backgrounds mixes
 * the state color with the primary label so it darkens in light mode and
 * lightens in dark mode. Severity color is reserved for severity.
 */

export const STYLE_ATTRIBUTE = 'dsh-security-plugin'

const tokens = /* css */ `
.dshsec-root {
  --dshsec-bg: var(--dsw-alias-bg-base, #ffffff);
  --dshsec-surface: var(--dsw-alias-bg-layer-2, #ffffff);
  --dshsec-field: var(--dsw-alias-bg-module-platform, #f5f6f7);
  --dshsec-field-hover: color-mix(in srgb, var(--dshsec-field) 94%, var(--dshsec-text));
  --dshsec-fill: var(--dsw-alias-interactive-bg-hover, rgba(38, 49, 72, 0.06));
  --dshsec-fill-strong: var(--dsw-alias-interactive-bg-active, rgba(38, 49, 72, 0.1));
  --dshsec-text: var(--dsw-alias-label-primary, #0f1115);
  --dshsec-text2: var(--dsw-alias-label-secondary, #61666b);
  /* DSH's tertiary label and link are under 4.5:1 on white; nudge them toward the primary label (AA in both themes). */
  --dshsec-text3: color-mix(in srgb, var(--dsw-alias-label-tertiary, #81858c) 78%, var(--dshsec-text));
  --dshsec-caption: var(--dsw-alias-label-caption, #adb2b8);
  --dshsec-line: var(--dsw-alias-border-l2, rgba(0, 0, 0, 0.1));
  --dshsec-line-strong: var(--dsw-alias-border-l4, rgba(0, 0, 0, 0.16));
  --dshsec-primary: var(--dsw-alias-button-primary-fill, #0f1115);
  --dshsec-primary-hover: var(--dsw-alias-button-primary-hover, #43454a);
  --dshsec-on-primary: var(--dsw-alias-label-primary-foreground, #ffffff);
  --dshsec-accent: var(--dsw-alias-state-business-primary, #4176e6);
  --dshsec-accent-ink: color-mix(in srgb, var(--dshsec-accent) 82%, var(--dshsec-text));
  --dshsec-accent-tint: var(--dsw-alias-state-business-tertiary, #e4edfd);
  --dshsec-focus: var(--dsw-alias-state-business-primary, #4176e6);
  --dshsec-link: color-mix(in srgb, var(--dsw-alias-link, #4176e6) 85%, var(--dshsec-text));
  --dshsec-err: var(--dsw-alias-state-error-primary, #ec1313);
  --dshsec-err-ink: color-mix(in srgb, var(--dshsec-err) 80%, var(--dshsec-text));
  --dshsec-err-tint: color-mix(in srgb, var(--dshsec-err) 9%, transparent);
  --dshsec-warn: var(--dsw-alias-state-warn-primary, #f59e0b);
  --dshsec-warn-ink: color-mix(in srgb, var(--dsw-alias-state-warn-label, #dd8629) 68%, var(--dshsec-text));
  --dshsec-warn-tint: var(--dsw-alias-state-warn-tertiary, #fef5e7);
  --dshsec-ok: var(--dsw-alias-state-success-primary, #22c55e);
  --dshsec-ok-ink: color-mix(in srgb, var(--dshsec-ok) 62%, var(--dshsec-text));
  --dshsec-ok-tint: var(--dsw-alias-state-success-tertiary, #e6faed);
  --dshsec-idle: var(--dsw-alias-state-idle-primary, #d4d4d4);
  --dshsec-code-bg: var(--dsw-alias-markdown-code-block, #f9fafb);
  --dshsec-card: var(--dsw-alias-settings-card-fill, #ffffff);
  --dshsec-card-line: var(--dsw-alias-border-l3, rgba(0, 0, 0, 0.12));
  --dshsec-track: color-mix(in srgb, var(--dshsec-text) 9%, transparent);
  --dshsec-mask: var(--dsw-alias-bg-mask-1, rgba(0, 0, 0, 0.24));
  --dshsec-shadow: 0 16px 40px rgba(0, 0, 0, 0.16), 0 2px 6px rgba(0, 0, 0, 0.06);
  --dshsec-mono: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, 'Liberation Mono', monospace;
  color: var(--dshsec-text);
  /* Use DSH's text font (and whatever the user or a locale plugin such as
     dsh-japanese set on it); only code-like text uses --dshsec-mono. */
  font-family: inherit;
  font-size: 14px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
  text-size-adjust: 100%;
}
.dshsec-root *, .dshsec-root *::before, .dshsec-root *::after { box-sizing: border-box; }
.dshsec-root :focus { outline: none; }
.dshsec-root :focus-visible { outline: 2px solid var(--dshsec-focus); outline-offset: 2px; }
.dshsec-root p { margin: 0; }
.dshsec-root h1, .dshsec-root h2, .dshsec-root h3, .dshsec-root h4 { margin: 0; }
.dshsec-visually-hidden {
  position: absolute !important; width: 1px; height: 1px; padding: 0; margin: -1px;
  overflow: hidden; clip: rect(0 0 0 0); white-space: nowrap; border: 0;
}
.dshsec-muted { color: var(--dshsec-text3); }
.dshsec-hint { color: var(--dshsec-text3); font-size: 12.5px; line-height: 1.6; }
.dshsec-num { font-variant-numeric: tabular-nums; }
.dshsec-mono, .dshsec-cell-mono { font-family: var(--dshsec-mono); font-size: 12.5px; }
.dshsec-link { color: var(--dshsec-link); text-decoration: none; overflow-wrap: anywhere; }
.dshsec-link:hover { text-decoration: underline; }
.dshsec-stack { display: grid; gap: 16px; min-width: 0; }
.dshsec-stack-sm { display: grid; gap: 8px; min-width: 0; }
.dshsec-stack-lg { display: grid; gap: 32px; min-width: 0; }
.dshsec-h2 { font-size: 16px; line-height: 24px; font-weight: 500; }
.dshsec-h3 { font-size: 14px; line-height: 22px; font-weight: 500; }
.dshsec-h4 { font-size: 13px; line-height: 20px; font-weight: 500; color: var(--dshsec-text2); }
.dshsec-list { margin: 0; padding-left: 1.25em; display: grid; gap: 4px; }
.dshsec-list li::marker { color: var(--dshsec-text3); }
`

const frame = /* css */ `
.dshsec-page {
  width: 100%; height: 100%; min-height: 0; display: flex; flex-direction: column;
  background: var(--dshsec-bg); container: dshsec-page / inline-size;
}
.dshsec-scroll { flex: 1 1 auto; min-height: 0; overflow: auto; overscroll-behavior: contain; scrollbar-gutter: stable; }
.dshsec-column { max-width: 1008px; margin: 0 auto; padding: 0 24px 48px; }
@container dshsec-page (max-width: 560px) { .dshsec-column { padding: 0 16px 32px; } }

.dshsec-head {
  padding-top: 28px; display: grid; grid-template-columns: minmax(0, 1fr) auto; align-items: center; gap: 6px 16px;
}
[data-platform='darwin'] .dshsec-head { padding-top: calc(28px + var(--dsh-frame-top-clearance, 0px)); }
.dshsec-title {
  font-size: 20px; line-height: 32px; font-weight: 500; min-width: 0;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dshsec-head-project { grid-column: 1 / -1; min-width: 0; display: flex; align-items: center; gap: 2px; }
.dshsec-add-project { min-width: 0; max-width: 100%; display: grid; gap: 8px; }
.dshsec-add-project--icon { display: inline-flex; flex: none; }
.dshsec-add-project .dshsec-btn { white-space: normal; text-align: start; }
.dshsec-project {
  position: relative; display: inline-flex; align-items: center; gap: 8px; min-width: 0; max-width: min(100%, 560px);
  height: 30px; padding: 0 8px; margin-left: -8px; border-radius: 8px; color: var(--dshsec-text3);
}
.dshsec-project svg { flex: none; }
.dshsec-project.is-picker { cursor: pointer; }
.dshsec-project.is-picker:hover:not(:disabled) { background: var(--dshsec-fill); }
.dshsec-project:focus-visible { outline: 2px solid var(--dshsec-focus); outline-offset: 0; }
.dshsec-project-title { color: var(--dshsec-text); font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 0 1 auto; min-width: 3em; }
.dshsec-project-path { font-size: 12.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; min-width: 0; flex: 1 1 0; }

.dshsec-tabs { display: flex; gap: 4px; margin: 12px 0 20px; overflow-x: auto; scrollbar-width: none; }
.dshsec-tabs::-webkit-scrollbar { display: none; }
.dshsec-tab {
  appearance: none; background: none; border: 0; cursor: pointer; font: inherit; font-size: 14px; line-height: 1;
  color: var(--dshsec-text3); height: 28px; padding: 0 12px; border-radius: 14px; white-space: nowrap; flex: none;
  transition: background-color 120ms ease, color 120ms ease;
}
.dshsec-tab:hover { color: var(--dshsec-text); background: var(--dshsec-fill); }
.dshsec-tab[aria-selected='true'] { color: var(--dshsec-text); background: var(--dshsec-fill-strong); }
.dshsec-tab:focus-visible { outline-offset: 0; }
@container dshsec-page (max-width: 420px) {
  .dshsec-tabs { gap: 2px; }
  .dshsec-tab { padding: 0 8px; }
}
.dshsec-tabpanel { min-width: 0; }
.dshsec-tabpanel:focus-visible { outline-offset: 6px; border-radius: 4px; }
.dshsec-banners { display: grid; gap: 8px; }
.dshsec-banners:not(:empty) { margin-bottom: 16px; }

/* Wide Findings: list and detail scroll independently below a fixed header. */
.dshsec-page--split .dshsec-scroll { overflow: hidden; display: flex; flex-direction: column; }
.dshsec-page--split .dshsec-column { flex: 1 1 auto; min-height: 0; width: 100%; display: flex; flex-direction: column; padding-bottom: 0; }
.dshsec-page--split .dshsec-column > * { flex: none; }
.dshsec-page--split .dshsec-column > .dshsec-tabpanel { flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; }
.dshsec-page--split .dshsec-findings-body { flex: 1 1 auto; min-height: 0; display: flex; flex-direction: column; gap: 12px; }
.dshsec-page--split .dshsec-findings-body > * { flex: none; }
.dshsec-page--split .dshsec-findings-body > .dshsec-findings { flex: 1 1 auto; }

.dshsec-loading { display: flex; align-items: center; gap: 10px; color: var(--dshsec-text3); padding: 24px 0; }
.dshsec-spinner {
  width: 14px; height: 14px; border-radius: 50%; border: 2px solid var(--dshsec-track);
  border-top-color: var(--dshsec-text2); animation: dshsec-spin 0.8s linear infinite; flex: none;
}
@keyframes dshsec-spin { to { transform: rotate(360deg); } }
/* Empty states follow DSH's: a glyph, one line, at most one sentence and one action, centered. */
.dshsec-empty {
  padding: 56px 16px; display: grid; justify-items: center; gap: 10px; text-align: center;
  max-width: 520px; margin: 0 auto;
}
.dshsec-empty-icon { color: var(--dshsec-text3); display: inline-flex; margin-bottom: 2px; }
.dshsec-empty-title { font-size: 15px; line-height: 22px; font-weight: 500; }
.dshsec-empty-body { color: var(--dshsec-text3); font-size: 13.5px; }
.dshsec-empty-action { margin-top: 6px; }
.dshsec-failure { display: grid; gap: 12px; }
`

const controls = /* css */ `
.dshsec-btn {
  appearance: none; display: inline-flex; align-items: center; justify-content: center; gap: 6px;
  height: 32px; padding: 0 14px; border-radius: 10px; border: 1px solid transparent;
  font: inherit; font-size: 14px; font-weight: 400; line-height: 1; cursor: pointer; white-space: nowrap;
  color: var(--dshsec-text); background: transparent;
  transition: background-color 120ms ease, border-color 120ms ease, color 120ms ease, opacity 120ms ease;
}
.dshsec-btn--sm { height: 28px; padding: 0 10px; font-size: 13px; border-radius: 8px; gap: 5px; }
.dshsec-btn-icon { display: inline-flex; }
.dshsec-btn--primary { background: var(--dshsec-primary); color: var(--dshsec-on-primary); font-weight: 500; }
.dshsec-btn--primary:hover:not(:disabled) { background: var(--dshsec-primary-hover); }
.dshsec-btn--secondary { border-color: var(--dshsec-line-strong); }
.dshsec-btn--secondary:hover:not(:disabled) { background: var(--dshsec-fill); }
.dshsec-btn--ghost { color: var(--dshsec-text2); }
.dshsec-btn--ghost:hover:not(:disabled) { background: var(--dshsec-fill); color: var(--dshsec-text); }
.dshsec-btn--danger { background: var(--dshsec-err); color: var(--dshsec-on-primary); font-weight: 500; }
.dshsec-btn--danger:hover:not(:disabled) { background: var(--dshsec-err-ink); }
.dshsec-btn--link { border: 0; padding: 0 2px; height: auto; color: var(--dshsec-link); font-weight: 400; border-radius: 4px; }
.dshsec-btn--link:hover:not(:disabled) { text-decoration: underline; }
.dshsec-btn:disabled { opacity: 0.45; cursor: not-allowed; }
.dshsec-btn[aria-busy='true'] { cursor: progress; opacity: 0.8; }
.dshsec-btn[aria-busy='true']::before {
  content: ''; width: 12px; height: 12px; border-radius: 50%; border: 2px solid currentColor;
  border-right-color: transparent; animation: dshsec-spin 0.8s linear infinite; flex: none;
}
.dshsec-btn[aria-busy='true'] .dshsec-btn-icon { display: none; }
.dshsec-btn--secondary.is-active { background: var(--dshsec-fill-strong); border-color: transparent; }
.dshsec-iconbtn {
  appearance: none; border: 0; background: none; color: var(--dshsec-text3); cursor: pointer; flex: none;
  width: 32px; height: 32px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center;
}
.dshsec-iconbtn:hover { background: var(--dshsec-fill); color: var(--dshsec-text); }
.dshsec-actions { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }

.dshsec-field { display: grid; gap: 6px; min-width: 0; align-content: start; }
.dshsec-label { font-size: 13px; font-weight: 500; color: var(--dshsec-text); line-height: 20px; }
.dshsec-field-error { color: var(--dshsec-err-ink); font-size: 12.5px; line-height: 1.5; }
.dshsec-input, .dshsec-textarea, .dshsec-select select, .dshsec-search input {
  font: inherit; font-size: 14px; color: var(--dshsec-text); background: var(--dshsec-field);
  border: 1px solid transparent; border-radius: 10px; width: 100%; min-width: 0;
  transition: background-color 120ms ease, border-color 120ms ease;
}
.dshsec-input:hover, .dshsec-textarea:hover, .dshsec-select select:hover:not(:disabled), .dshsec-search input:hover {
  background: var(--dshsec-field-hover);
}
.dshsec-input::placeholder, .dshsec-textarea::placeholder, .dshsec-search input::placeholder { color: var(--dshsec-text3); }
.dshsec-input { height: 34px; padding: 0 12px; }
.dshsec-input--num { font-variant-numeric: tabular-nums; max-width: 220px; }
.dshsec-textarea { padding: 8px 12px; resize: vertical; line-height: 1.55; min-height: 64px; display: block; }
.dshsec-input:focus-visible, .dshsec-textarea:focus-visible, .dshsec-select select:focus-visible, .dshsec-search input:focus-visible {
  outline: 2px solid var(--dshsec-focus); outline-offset: 0;
}
.dshsec-input[aria-invalid='true'], .dshsec-select select[aria-invalid='true'] { border-color: var(--dshsec-err); }
.dshsec-select { position: relative; display: inline-flex; min-width: 0; max-width: 100%; }
.dshsec-field .dshsec-select { display: flex; }
.dshsec-select select {
  appearance: none; height: 34px; padding: 0 32px 0 12px; cursor: pointer;
  text-overflow: ellipsis; white-space: nowrap; overflow: hidden;
}
.dshsec-select select:disabled { opacity: 0.5; cursor: not-allowed; }
.dshsec-select::after {
  content: ''; position: absolute; right: 13px; top: 50%; width: 6px; height: 6px; pointer-events: none;
  border-right: 1.5px solid var(--dshsec-text3); border-bottom: 1.5px solid var(--dshsec-text3);
  transform: translateY(-70%) rotate(45deg);
}
.dshsec-select option, .dshsec-select optgroup { color: initial; }
.dshsec-check { display: flex; gap: 10px; align-items: flex-start; cursor: pointer; line-height: 1.55; }
.dshsec-check input { margin: 3px 0 0; width: 16px; height: 16px; accent-color: var(--dshsec-primary); flex: none; cursor: pointer; }
.dshsec-fieldset { border: 0; margin: 0; padding: 0; min-width: 0; display: grid; gap: 10px; }
.dshsec-fieldset > legend { padding: 0; margin-bottom: 10px; }

.dshsec-toggle-row { display: flex; gap: 16px; align-items: flex-start; justify-content: space-between; }
.dshsec-toggle-text { display: grid; gap: 2px; min-width: 0; }
.dshsec-toggle-note { font-size: 12.5px; color: var(--dshsec-warn-ink); }
.dshsec-switch {
  appearance: none; flex: none; position: relative; width: 36px; height: 20px; margin-top: 1px; padding: 0;
  border-radius: 10px; border: 0; background: var(--dshsec-idle); cursor: pointer; transition: background-color 140ms ease;
}
.dshsec-switch-thumb {
  position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 50%;
  background: var(--dsw-alias-switch-thumb, #ffffff); box-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
  transition: transform 140ms ease, background-color 140ms ease;
}
.dshsec-switch[aria-checked='true'] { background: var(--dshsec-primary); }
.dshsec-switch[aria-checked='true'] .dshsec-switch-thumb { transform: translateX(16px); background: var(--dshsec-on-primary); }
.dshsec-switch:disabled { opacity: 0.4; cursor: not-allowed; }
.dshsec-switch:focus-visible { border-radius: 10px; }

.dshsec-callout {
  display: flex; gap: 10px; align-items: flex-start; padding: 10px 14px; border-radius: 10px;
  background: var(--dshsec-fill); color: var(--dshsec-text);
}
.dshsec-callout-icon { flex: none; display: inline-flex; margin-top: 3px; color: var(--dshsec-text3); }
.dshsec-callout-main { flex: 1 1 auto; min-width: 0; display: grid; gap: 2px; }
.dshsec-callout-title { font-weight: 500; }
.dshsec-callout-body { color: var(--dshsec-text2); overflow-wrap: anywhere; }
.dshsec-callout-title + .dshsec-callout-body { font-size: 13px; }
.dshsec-callout-action { flex: none; align-self: center; }
.dshsec-callout--info .dshsec-callout-icon { color: var(--dshsec-accent); }
.dshsec-callout--success { background: var(--dshsec-ok-tint); }
.dshsec-callout--success .dshsec-callout-icon { color: var(--dshsec-ok-ink); }
.dshsec-callout--warn { background: var(--dshsec-warn-tint); }
.dshsec-callout--warn .dshsec-callout-icon { color: var(--dshsec-warn); }
.dshsec-callout--warn .dshsec-callout-title { color: var(--dshsec-warn-ink); }
.dshsec-callout--error { background: var(--dshsec-err-tint); }
.dshsec-callout--error .dshsec-callout-icon, .dshsec-callout--error .dshsec-callout-title { color: var(--dshsec-err-ink); }
@container (max-width: 480px) {
  .dshsec-callout { flex-wrap: wrap; }
  .dshsec-callout-action { flex-basis: 100%; padding-left: 26px; }
}

.dshsec-badge {
  display: inline-flex; align-items: center; justify-content: center; height: 20px; padding: 0 7px; border-radius: 6px;
  font-size: 12px; font-weight: 500; line-height: 1; white-space: nowrap; flex: none;
  background: var(--dshsec-fill-strong); color: var(--dshsec-text2);
}
.dshsec-badge--quiet { background: transparent; box-shadow: inset 0 0 0 1px var(--dshsec-line-strong); color: var(--dshsec-text3); font-weight: 400; }
.dshsec-badge--brand { background: var(--dshsec-accent-tint); color: var(--dshsec-accent-ink); }
.dshsec-badge--success { background: var(--dshsec-ok-tint); color: var(--dshsec-ok-ink); }
.dshsec-badge--warn { background: var(--dshsec-warn-tint); color: var(--dshsec-warn-ink); }
.dshsec-badge--error { background: var(--dshsec-err-tint); color: var(--dshsec-err-ink); }
.dshsec-badge--error-strong { background: var(--dshsec-err); color: var(--dshsec-on-primary); }

/* Severity is the only colored element of a finding: a dot and the word. */
.dshsec-sev { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; font-size: 13px; color: var(--dshsec-text2); }
.dshsec-sev-dot { width: 8px; height: 8px; border-radius: 50%; flex: none; background: var(--dshsec-caption); }
.dshsec-sev--critical { color: var(--dshsec-err-ink); font-weight: 500; }
.dshsec-sev--critical .dshsec-sev-dot { background: var(--dshsec-err); }
.dshsec-sev--high .dshsec-sev-dot { background: color-mix(in srgb, var(--dshsec-err) 55%, var(--dshsec-warn)); }
.dshsec-sev--medium .dshsec-sev-dot { background: var(--dshsec-warn); }
.dshsec-sev--low .dshsec-sev-dot { background: var(--dshsec-text3); }
.dshsec-verif { font-size: 12.5px; color: var(--dshsec-text2); white-space: nowrap; }
.dshsec-verif--strong_static_evidence, .dshsec-verif--proven_dynamic { color: var(--dshsec-text); }
.dshsec-verif--refuted { color: var(--dshsec-text3); }
.dshsec-status { display: inline-flex; align-items: center; gap: 6px; white-space: nowrap; }
.dshsec-status-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; background: var(--dshsec-line-strong); }
.dshsec-status--running .dshsec-status-dot { background: var(--dshsec-accent); }
.dshsec-status--completed .dshsec-status-dot { background: var(--dshsec-ok); }
.dshsec-status--failed { color: var(--dshsec-err-ink); }
.dshsec-status--failed .dshsec-status-dot { background: var(--dshsec-err); }
.dshsec-status--interrupted .dshsec-status-dot { background: var(--dshsec-warn); }
.dshsec-quote { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--dshsec-text3); white-space: nowrap; }
.dshsec-quote--mismatch { color: var(--dshsec-warn-ink); font-weight: 500; }

.dshsec-menu-wrap { position: relative; display: inline-flex; }
.dshsec-menu {
  position: absolute; top: calc(100% + 4px); z-index: 20; min-width: 160px; padding: 4px;
  background: var(--dshsec-surface); border: 1px solid var(--dshsec-line); border-radius: 12px;
  box-shadow: var(--dshsec-shadow); display: grid;
}
.dshsec-menu-layer { position: fixed; inset: 0; z-index: 30; pointer-events: none; }
.dshsec-menu-panel { pointer-events: auto; min-width: 0; overflow-y: auto; overflow-x: hidden; overscroll-behavior: contain; }
.dshsec-menu-panel > .dshsec-menu-item { min-width: 0; white-space: normal; overflow-wrap: anywhere; }
.dshsec-menu--end { right: 0; }
.dshsec-menu--start { left: 0; }
.dshsec-menu-item {
  appearance: none; border: 0; background: none; font: inherit; color: var(--dshsec-text); text-align: left;
  padding: 7px 10px; border-radius: 8px; cursor: pointer;
}
.dshsec-menu-item:hover, .dshsec-menu-item:focus-visible { background: var(--dshsec-fill); outline-offset: -2px; }
.dshsec-menu-item--check { display: flex; align-items: center; gap: 8px; padding-left: 8px; }
.dshsec-menu-check { width: 14px; display: inline-flex; flex: none; color: var(--dshsec-text); }

.dshsec-projsel { min-width: 0; max-width: 100%; }
.dshsec-projsel--quiet { display: inline-flex; max-width: min(100%, 560px); }
.dshsec-projsel--quiet .dshsec-project { max-width: 100%; }
.dshsec-projsel-trigger { appearance: none; display: flex; align-items: center; gap: 8px; font: inherit; text-align: start; cursor: pointer; }
.dshsec-projsel--quiet .dshsec-projsel-trigger { border: 0; background: none; }
.dshsec-projsel--field { width: 100%; }
.dshsec-projsel--field .dshsec-projsel-trigger:hover:not(:disabled) { background: var(--dshsec-field-hover); }
.dshsec-projsel--field .dshsec-projsel-trigger:disabled { background: var(--dshsec-field); }
.dshsec-projsel-trigger:disabled { opacity: 0.5; cursor: not-allowed; }
.dshsec-projsel-trigger > svg { flex: none; color: var(--dshsec-text3); }
.dshsec-projsel-trigger > svg:last-child { margin-left: auto; }
.dshsec-projsel-layer { position: fixed; inset: 0; z-index: 30; pointer-events: none; }
.dshsec-projsel-panel { pointer-events: auto; min-width: 0; overflow-y: auto; overscroll-behavior: contain; }
.dshsec-projsel-option { display: flex; align-items: center; gap: 8px; min-width: 0; width: 100%; }
.dshsec-projsel-check { display: flex; align-items: center; justify-content: center; width: 16px; flex: none; }
.dshsec-projsel-text { display: grid; min-width: 0; gap: 1px; flex: 1; }
.dshsec-projsel-line { display: flex; align-items: baseline; gap: 12px; min-width: 0; }
.dshsec-projsel-title { color: var(--dshsec-text); font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; min-width: 0; }
.dshsec-projsel-status {
  margin-left: auto; flex: none; display: inline-flex; align-items: center; gap: 6px;
  font-size: 12px; color: var(--dshsec-text3); white-space: nowrap;
}
.dshsec-projsel-status.is-active { color: var(--dshsec-accent-ink); }
.dshsec-projsel-status.is-warn { color: var(--dshsec-warn-ink); }
.dshsec-projsel-status.is-error { color: var(--dshsec-err-ink); }
.dshsec-projsel-dot { width: 6px; height: 6px; border-radius: 50%; flex: none; background: var(--dshsec-line-strong); }
.dshsec-projsel-status.is-none .dshsec-projsel-dot { display: none; }
.dshsec-projsel-status.is-active .dshsec-projsel-dot { background: var(--dshsec-accent); animation: dshsec-pulse 1.6s ease-out infinite; }
.dshsec-projsel-status.is-warn .dshsec-projsel-dot { background: var(--dshsec-warn); }
.dshsec-projsel-status.is-error .dshsec-projsel-dot { background: var(--dshsec-err); }
.dshsec-projsel-dot.dshsec-sev--critical { background: var(--dshsec-err); }
.dshsec-projsel-dot.dshsec-sev--high { background: color-mix(in srgb, var(--dshsec-err) 55%, var(--dshsec-warn)); }
.dshsec-projsel-dot.dshsec-sev--medium { background: var(--dshsec-warn); }
.dshsec-projsel-path { color: var(--dshsec-text2); font-size: 12.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; direction: rtl; unicode-bidi: plaintext; text-align: left; }

.dshsec-table-wrap { overflow-x: auto; min-width: 0; }
.dshsec-table { width: 100%; border-collapse: collapse; font-size: 13px; }
.dshsec-table th {
  text-align: left; font-weight: 400; color: var(--dshsec-text3); font-size: 12px;
  padding: 6px 12px 6px 0; border-bottom: 1px solid var(--dshsec-line); white-space: nowrap;
}
.dshsec-table td { padding: 8px 12px 8px 0; border-bottom: 1px solid var(--dshsec-line); vertical-align: middle; }
.dshsec-table tr:last-child td { border-bottom: 0; }
.dshsec-table .dshsec-num { text-align: right; }
.dshsec-cell-wrap { min-width: 160px; overflow-wrap: anywhere; }

.dshsec-disclosure > summary {
  cursor: pointer; color: var(--dshsec-text2); width: fit-content; border-radius: 4px; list-style: none;
  display: inline-flex; align-items: center; gap: 6px;
}
.dshsec-disclosure > summary::-webkit-details-marker { display: none; }
.dshsec-disclosure > summary::before {
  content: ''; width: 5px; height: 5px; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor;
  transform: rotate(-45deg); transition: transform 120ms ease; margin: 0 2px;
}
.dshsec-disclosure[open] > summary::before { transform: rotate(45deg); }
.dshsec-disclosure > summary:hover { color: var(--dshsec-text); }
.dshsec-disclosure[open] > summary { margin-bottom: 4px; }
/* Usage, reviewers and activity inside one disclosure read as separate blocks. */
.dshsec-disclosure-body { display: grid; gap: 24px; min-width: 0; padding-top: 8px; }
.dshsec-technical { font-size: 12.5px; color: var(--dshsec-text3); overflow-wrap: anywhere; }
.dshsec-advanced { border-radius: 8px; }
.dshsec-advanced > summary {
  cursor: pointer; color: var(--dshsec-text3); font-size: 12.5px; width: fit-content; border-radius: 4px;
  list-style: none; display: inline-flex; align-items: center; gap: 4px;
}
.dshsec-advanced > summary::-webkit-details-marker { display: none; }
.dshsec-advanced > summary::before {
  content: ''; width: 5px; height: 5px; border-right: 1.5px solid currentColor; border-bottom: 1.5px solid currentColor;
  transform: rotate(-45deg); transition: transform 120ms ease; margin: 0 3px 0 1px;
}
.dshsec-advanced[open] > summary::before { transform: rotate(45deg); }
.dshsec-advanced > summary:hover { color: var(--dshsec-text); }
.dshsec-advanced-body { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; padding-top: 10px; }
`

const modal = /* css */ `
.dshsec-modal-backdrop {
  position: fixed; inset: 0; z-index: 1000; display: flex; align-items: center; justify-content: center;
  padding: 16px; background: var(--dshsec-mask);
}
/* Large dialogs change height as choices change; anchor them so the header stays put. */
.dshsec-modal-backdrop:has(.dshsec-modal--lg) { align-items: flex-start; padding-top: clamp(16px, 8vh, 96px); }
.dshsec-modal {
  width: 100%; max-height: calc(100vh - 32px); max-height: calc(100dvh - 32px);
  animation: dshsec-modal-in 140ms ease-out; display: flex; flex-direction: column;
  background: var(--dshsec-surface); color: var(--dshsec-text); border-radius: 16px;
  border: 1px solid var(--dshsec-line); box-shadow: var(--dshsec-shadow); container-type: inline-size;
}
.dshsec-modal:focus { outline: none; }
.dshsec-modal--lg { max-height: calc(100vh - clamp(16px, 8vh, 96px) - 16px); max-height: calc(100dvh - clamp(16px, 8vh, 96px) - 16px); }
@keyframes dshsec-modal-in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
.dshsec-modal--sm { max-width: 440px; }
.dshsec-modal--md { max-width: 560px; }
.dshsec-modal--lg { max-width: 680px; }
.dshsec-modal-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 16px 16px 8px 24px; }
.dshsec-modal-title { font-size: 16px; line-height: 24px; font-weight: 500; }
.dshsec-modal-body { padding: 4px 24px 20px; overflow: auto; display: grid; gap: 20px; overscroll-behavior: contain; }
.dshsec-modal-foot {
  display: flex; justify-content: flex-end; align-items: center; gap: 8px; flex-wrap: wrap;
  padding: 12px 24px 16px; border-top: 1px solid var(--dshsec-line);
}
.dshsec-modal-foot-note { margin-right: auto; font-size: 12.5px; color: var(--dshsec-text3); min-width: 0; }
@media (max-width: 520px) {
  .dshsec-modal-backdrop, .dshsec-modal-backdrop:has(.dshsec-modal--lg) { padding: 8px; align-items: flex-end; }
  .dshsec-modal, .dshsec-modal--lg { max-height: calc(100vh - 16px); max-height: calc(100dvh - 16px); border-radius: 16px; }
  .dshsec-modal-head { padding: 12px 8px 6px 16px; }
  .dshsec-modal-body { padding: 4px 16px 16px; }
  .dshsec-modal-foot { padding: 10px 16px 12px; }
  .dshsec-modal-foot .dshsec-btn { flex: 1 1 auto; }
  .dshsec-modal-foot-note { flex-basis: 100%; }
}
.dshsec-subsection { display: grid; gap: 10px; min-width: 0; }
.dshsec-subhead { display: flex; align-items: baseline; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.dshsec-kv { margin: 0; display: grid; gap: 6px; }
.dshsec-kv-row { display: grid; grid-template-columns: minmax(110px, 180px) minmax(0, 1fr); gap: 12px; align-items: baseline; }
.dshsec-kv-row dt { color: var(--dshsec-text3); font-size: 13px; }
.dshsec-kv-row dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
.dshsec-kv-row dd .dshsec-meter { margin-top: 6px; }
@container (max-width: 520px) { .dshsec-kv-row { grid-template-columns: minmax(0, 1fr); gap: 0; } }
/* New scan form: a label column and controls, like DSH's settings rows. */
.dshsec-form { gap: 18px; }
.dshsec-form-row { display: grid; grid-template-columns: 112px minmax(0, 1fr); gap: 6px 16px; align-items: start; min-width: 0; border: 0; margin: 0; padding: 0; }
.dshsec-form-row > legend { float: left; padding: 0; }
.dshsec-form-label { font-size: 13px; line-height: 34px; color: var(--dshsec-text2); }
.dshsec-form-control { display: grid; gap: 6px; min-width: 0; align-content: start; }
.dshsec-form-control > p { line-height: 1.6; }
.dshsec-form-control > .dshsec-num:first-child, .dshsec-form-control > .dshsec-stack-xs:first-child,
.dshsec-form-control > .dshsec-route-model:first-child, .dshsec-form-control > .dshsec-muted:first-child { padding-top: 7px; }
.dshsec-form-inline { display: flex; align-items: center; gap: 4px 8px; min-width: 0; min-height: 34px; }
.dshsec-form-inline > .dshsec-projsel { flex: 1 1 0; min-width: 0; }
.dshsec-form-inline > .dshsec-route-model, .dshsec-form-inline > .dshsec-routes { min-width: 0; }
.dshsec-form-extra { justify-self: start; }
.dshsec-form-note { margin-top: -6px; }
.dshsec-label--sub { font-weight: 400; color: var(--dshsec-text2); }
@container (max-width: 520px) {
  .dshsec-form-row { grid-template-columns: minmax(0, 1fr); gap: 4px; }
  .dshsec-form-label { line-height: 20px; }
  .dshsec-form-control > .dshsec-num:first-child, .dshsec-form-control > .dshsec-stack-xs:first-child,
  .dshsec-form-control > .dshsec-route-model:first-child, .dshsec-form-control > .dshsec-muted:first-child { padding-top: 0; }
}
/* Review depth as one segmented control (native radios keep arrow-key behavior). */
.dshsec-modes { display: inline-flex; flex-wrap: wrap; gap: 2px; padding: 3px; border-radius: 10px; background: var(--dshsec-fill); justify-self: start; max-width: 100%; }
.dshsec-mode {
  position: relative; display: inline-flex; align-items: center; height: 28px; padding: 0 12px; border-radius: 8px;
  font-size: 13px; color: var(--dshsec-text2); cursor: pointer; white-space: nowrap;
  transition: background-color 120ms ease, color 120ms ease;
}
.dshsec-mode:hover { color: var(--dshsec-text); }
.dshsec-mode input { position: absolute; opacity: 0; pointer-events: none; }
.dshsec-mode.is-selected { background: var(--dshsec-surface); color: var(--dshsec-text); font-weight: 500; box-shadow: 0 1px 2px rgba(0, 0, 0, 0.1); }
.dshsec-mode:has(input:focus-visible) { outline: 2px solid var(--dshsec-focus); outline-offset: 1px; }
.dshsec-consent {
  display: grid; gap: 8px; padding: 14px 16px; border-radius: 12px; border: 1px solid var(--dshsec-line-strong);
}
.dshsec-consent.is-invalid { box-shadow: inset 0 0 0 1px var(--dshsec-err); }
.dshsec-routes { margin: 0; padding: 0; list-style: none; display: grid; gap: 4px; }
.dshsec-routes li { display: flex; gap: 10px; align-items: baseline; flex-wrap: wrap; min-width: 0; }
.dshsec-routes .dshsec-route-role { color: var(--dshsec-text3); font-size: 13px; min-width: 7em; }
.dshsec-routes .dshsec-route-model { min-width: 0; overflow-wrap: anywhere; }
`

const overview = /* css */ `
.dshsec-meta { display: flex; align-items: center; gap: 2px 12px; flex-wrap: wrap; font-size: 13px; margin-top: 2px; color: var(--dshsec-text3); }
.dshsec-stack-xs { display: grid; gap: 4px; min-width: 0; }
.dshsec-plain-list { list-style: none; margin: 0; padding: 0; display: grid; gap: 2px; }

.dshsec-card {
  display: grid; gap: 20px; padding: 20px 24px; border-radius: 16px; min-width: 0;
  background: var(--dshsec-card); border: 1px solid var(--dshsec-card-line);
}
@container dshsec-page (max-width: 560px) { .dshsec-card { padding: 16px; gap: 16px; } }
.dshsec-card-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px 16px; flex-wrap: wrap; }
.dshsec-card-actions { display: flex; gap: 8px; flex-wrap: wrap; }
.dshsec-problem--failed { border-color: color-mix(in srgb, var(--dshsec-err) 40%, transparent); }
.dshsec-problem--interrupted { border-color: color-mix(in srgb, var(--dshsec-warn) 45%, transparent); }
.dshsec-queue { display: flex; align-items: baseline; gap: 4px 12px; flex-wrap: wrap; color: var(--dshsec-text2); }

.dshsec-progress-grid { display: grid; grid-template-columns: minmax(170px, 210px) minmax(0, 1fr); gap: 20px 32px; align-items: start; }
@container dshsec-page (max-width: 640px) { .dshsec-progress-grid { grid-template-columns: minmax(0, 1fr); } }
.dshsec-progress-main { display: grid; gap: 18px; min-width: 0; }
.dshsec-now { display: grid; gap: 8px; }
.dshsec-now-line { display: flex; justify-content: space-between; align-items: baseline; gap: 4px 12px; flex-wrap: wrap; }
.dshsec-now-phase { font-size: 15px; font-weight: 500; }
.dshsec-now-count { font-size: 13px; color: var(--dshsec-text3); font-variant-numeric: tabular-nums; }

.dshsec-steps { list-style: none; margin: 0; padding: 0; display: grid; }
.dshsec-step {
  position: relative; display: grid; grid-template-columns: 14px minmax(0, 1fr) auto; gap: 10px; align-items: center;
  min-height: 26px; font-size: 13px; color: var(--dshsec-text3);
}
.dshsec-step:not(:last-child)::before {
  content: ''; position: absolute; left: 6.5px; top: 18px; height: calc(100% - 10px); width: 1px; background: var(--dshsec-line);
}
.dshsec-step-dot {
  position: relative; width: 9px; height: 9px; border-radius: 50%; justify-self: center;
  border: 1.5px solid var(--dshsec-line-strong); background: var(--dshsec-card);
}
.dshsec-step-label { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dshsec-step-tag { font-size: 11.5px; color: var(--dshsec-text3); }
.dshsec-step--done { color: var(--dshsec-text2); }
.dshsec-step--done .dshsec-step-dot { background: var(--dshsec-text3); border-color: var(--dshsec-text3); }
.dshsec-step--skipped { color: var(--dshsec-text3); }
.dshsec-step--skipped .dshsec-step-label { opacity: 0.7; }
.dshsec-step--skipped .dshsec-step-dot { border-style: dashed; }
.dshsec-step--running { color: var(--dshsec-text); font-weight: 500; }
.dshsec-step--running .dshsec-step-dot {
  background: var(--dshsec-accent); border-color: var(--dshsec-accent);
  animation: dshsec-pulse 1.6s ease-out infinite;
}
@keyframes dshsec-pulse {
  0% { box-shadow: 0 0 0 0 color-mix(in srgb, var(--dshsec-accent) 45%, transparent); }
  100% { box-shadow: 0 0 0 6px transparent; }
}
.dshsec-meter { height: 4px; border-radius: 2px; background: var(--dshsec-track); overflow: hidden; }
.dshsec-meter > span { display: block; height: 100%; border-radius: inherit; background: var(--dshsec-text3); transition: width 400ms ease; }
.dshsec-meter--strong { height: 6px; border-radius: 3px; }
.dshsec-meter--strong > span { background: var(--dshsec-accent); }
.dshsec-meter--warn > span { background: var(--dshsec-warn); }
.dshsec-usage { margin: 0; display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 16px; }
@container dshsec-page (max-width: 480px) { .dshsec-usage { grid-template-columns: minmax(0, 1fr); gap: 12px; } }
.dshsec-usage-row { display: grid; gap: 4px; min-width: 0; }
.dshsec-usage-row dt { font-size: 12px; color: var(--dshsec-text3); }
.dshsec-usage-row dd { margin: 0; display: grid; gap: 6px; }
.dshsec-usage-value { font-size: 13.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dshsec-usage-max { color: var(--dshsec-text3); }
.dshsec-wstate { font-size: 12.5px; color: var(--dshsec-text3); white-space: nowrap; display: inline-flex; align-items: center; gap: 6px; }
.dshsec-wstate::before { content: ''; width: 6px; height: 6px; border-radius: 50%; background: var(--dshsec-line-strong); }
.dshsec-wstate--running { color: var(--dshsec-text); }
.dshsec-wstate--running::before { background: var(--dshsec-accent); }
.dshsec-wstate--done::before { background: var(--dshsec-text3); }
.dshsec-wstate--failed { color: var(--dshsec-err-ink); }
.dshsec-wstate--failed::before { background: var(--dshsec-err); }
@container dshsec-page (max-width: 760px) { .dshsec-col-opt { display: none; } }
/* Reserve the rows so the card does not grow while reviewers start and finish. */
.dshsec-workers .dshsec-table-wrap, .dshsec-workers > .dshsec-muted { min-height: 222px; }
.dshsec-workers .dshsec-table { table-layout: fixed; }
.dshsec-workers .dshsec-table th { height: 30px; box-sizing: border-box; }
.dshsec-workers .dshsec-table td { padding-top: 0; padding-bottom: 0; height: 38px; box-sizing: border-box; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dshsec-workers .dshsec-cell-wrap { min-width: 0; }
.dshsec-workers .dshsec-w-role { width: 8em; }
.dshsec-workers .dshsec-w-model { width: 28%; }
.dshsec-workers .dshsec-w-state { width: 6.5em; }
.dshsec-workers .dshsec-w-turns { width: 6em; }
.dshsec-root:lang(en) .dshsec-workers .dshsec-w-role { width: 7.5em; }
.dshsec-root:lang(en) .dshsec-workers .dshsec-w-turns { width: 5em; }
.dshsec-feed {
  list-style: none; margin: 0; padding: 8px 12px; height: 220px; overflow: auto; overscroll-behavior: contain;
  background: var(--dshsec-code-bg); border: 1px solid var(--dshsec-line); border-radius: 10px;
  font-size: 12.5px; line-height: 1.6; display: grid; gap: 1px; align-content: start;
}
.dshsec-feed-item { display: grid; grid-template-columns: auto minmax(0, 1fr); gap: 10px; }
.dshsec-feed-time { font-family: var(--dshsec-mono); font-size: 11.5px; color: var(--dshsec-text3); font-variant-numeric: tabular-nums; }
.dshsec-feed-msg { color: var(--dshsec-text2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.dshsec-feed-detail { margin-left: 8px; color: var(--dshsec-text3); }
.dshsec-feed-item--debug .dshsec-feed-msg { color: var(--dshsec-text3); }
.dshsec-feed-item--warn .dshsec-feed-msg { color: var(--dshsec-warn-ink); }
.dshsec-feed-item--error .dshsec-feed-msg { color: var(--dshsec-err-ink); }

/* Results: summary line, counts, the findings themselves, then coverage. */
.dshsec-results { display: grid; gap: 24px; min-width: 0; }
.dshsec-results-head { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px 16px; flex-wrap: wrap; }
.dshsec-review-line { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--dshsec-text3); margin-top: 2px; }
.dshsec-review-line svg { flex: none; }
.dshsec-review-line.is-warn { color: var(--dshsec-warn-ink); }
.dshsec-review-line.is-error { color: var(--dshsec-err-ink); }
.dshsec-budget-stop { display: grid; gap: 8px; }
/* Open findings per severity: one quiet row of counts that open the filtered list. No tiles or big numbers. */
.dshsec-sevsum { display: grid; gap: 4px; }
.dshsec-sevsum-row { list-style: none; margin: 0 0 0 -10px; padding: 0; display: flex; flex-wrap: wrap; gap: 2px 4px; }
.dshsec-sevsum-item {
  appearance: none; border: 0; background: none; font: inherit; color: var(--dshsec-text3); cursor: pointer;
  display: inline-flex; align-items: center; gap: 6px; height: 30px; padding: 0 10px; border-radius: 8px; white-space: nowrap;
}
.dshsec-sevsum-item:hover { background: var(--dshsec-fill); color: var(--dshsec-text); }
.dshsec-sevsum-item:focus-visible { outline-offset: -2px; }
.dshsec-sevsum-count { font-weight: 600; font-variant-numeric: tabular-nums; }
.dshsec-sevsum-item.has-value { color: var(--dshsec-text); }
.dshsec-sevsum-item.dshsec-sev--critical.has-value { color: var(--dshsec-err-ink); }
.dshsec-sevsum-item:not(.has-value) .dshsec-sev-dot { background: var(--dshsec-track); }
.dshsec-sevsum .dshsec-meta { margin-top: 0; }
.dshsec-coverage .dshsec-kv { gap: 8px; }
`

const findings = /* css */ `
.dshsec-findings { display: grid; gap: 16px; min-width: 0; }
.dshsec-findings.is-split {
  flex: 1 1 auto; min-height: 0; grid-template-columns: minmax(300px, 380px) minmax(0, 1fr);
  grid-template-rows: minmax(0, 1fr); gap: 0;
}
.dshsec-findings-list { display: grid; gap: 14px; min-width: 0; align-content: start; }
.dshsec-findings.is-split > .dshsec-findings-list,
.dshsec-findings.is-split > .dshsec-findings-detail {
  min-height: 0; overflow: auto; overscroll-behavior: contain; scrollbar-gutter: stable;
}
.dshsec-findings.is-split > .dshsec-findings-list { padding: 2px 16px 32px 2px; }
.dshsec-findings.is-split > .dshsec-findings-detail { padding: 2px 4px 40px 28px; border-left: 1px solid var(--dshsec-line); }
.dshsec-findings-detail { min-width: 0; display: grid; gap: 12px; align-content: start; }
.dshsec-findings-detail--empty { align-content: start; padding-top: 48px !important; color: var(--dshsec-text3); }
.dshsec-back { justify-self: start; margin-left: -10px; }

.dshsec-filters { display: grid; gap: 8px; }
.dshsec-search { position: relative; display: flex; align-items: center; }
.dshsec-search svg { position: absolute; left: 11px; color: var(--dshsec-text3); pointer-events: none; }
.dshsec-search input { height: 34px; padding: 0 12px 0 34px; }
.dshsec-filter-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.dshsec-filter-row .dshsec-btn--secondary { border-color: var(--dshsec-line); color: var(--dshsec-text2); }
.dshsec-filter-row .dshsec-btn--secondary.is-active { color: var(--dshsec-text); }
.dshsec-count { font-size: 12.5px; margin-left: auto; white-space: nowrap; }

/* Finding rows: the severity column hugs the widest badge (subgrid), so titles align. */
.dshsec-flist { list-style: none; margin: 0; padding: 0; display: grid; grid-template-columns: max-content minmax(0, 1fr); column-gap: 12px; }
.dshsec-flist > li { grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; border-top: 1px solid var(--dshsec-line); }
.dshsec-flist > li:last-child { border-bottom: 1px solid var(--dshsec-line); }
.dshsec-frow {
  appearance: none; border: 0; background: none; font: inherit; color: inherit; text-align: left; cursor: pointer;
  grid-column: 1 / -1; display: grid; grid-template-columns: subgrid; align-items: start;
  padding: 9px 10px; border-radius: 8px; margin: 2px 0; position: relative;
  transition: background-color 100ms ease;
}
@supports not (grid-template-columns: subgrid) {
  .dshsec-flist { grid-template-columns: minmax(0, 1fr); }
  .dshsec-flist > li { display: block; }
  .dshsec-frow { width: 100%; grid-template-columns: auto minmax(0, 1fr); column-gap: 12px; }
}
.dshsec-frow:hover { background: var(--dshsec-fill); }
.dshsec-frow:focus-visible { outline-offset: -2px; }
.dshsec-frow.is-selected { background: var(--dshsec-fill-strong); }
.dshsec-frow.is-selected::before {
  content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px; border-radius: 2px; background: var(--dshsec-text);
}
.dshsec-frow.is-ruled-out .dshsec-frow-title { color: var(--dshsec-text3); }
.dshsec-frow-sev { padding-top: 1px; display: flex; min-width: 5.5em; }
.dshsec-frow-main { display: grid; gap: 3px; min-width: 0; }
.dshsec-frow-title {
  font-weight: 500; line-height: 1.5; overflow-wrap: anywhere;
  display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden;
}
.dshsec-frow-meta { display: flex; align-items: center; gap: 4px 10px; flex-wrap: wrap; font-size: 12.5px; min-width: 0; }
.dshsec-frow-loc {
  font-family: var(--dshsec-mono); font-size: 12px; color: var(--dshsec-text3); min-width: 0; flex: 0 1 auto;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.dshsec-frow .dshsec-badge { height: 18px; font-size: 11.5px; padding: 0 6px; }

.dshsec-detail { display: grid; gap: 0; max-width: 820px; min-width: 0; }
.dshsec-detail-head { display: grid; gap: 6px; padding-bottom: 18px; }
.dshsec-detail-tags { display: flex; gap: 4px 14px; flex-wrap: wrap; align-items: center; font-size: 13px; }
.dshsec-detail-title { font-size: 18px; line-height: 26px; font-weight: 500; overflow-wrap: anywhere; border-radius: 4px; }
.dshsec-detail-loc { font-family: var(--dshsec-mono); font-size: 12.5px; color: var(--dshsec-text3); overflow-wrap: anywhere; }
.dshsec-detail-head > .dshsec-stack-sm { margin-top: 6px; }
.dshsec-dsec { display: grid; gap: 10px; padding: 18px 0; border-top: 1px solid var(--dshsec-line); min-width: 0; }
.dshsec-dsec-title { font-size: 14px; line-height: 22px; font-weight: 500; }
.dshsec-dsec-body { display: grid; gap: 12px; color: var(--dshsec-text); min-width: 0; }
.dshsec-dsec-body > p, .dshsec-review p { max-width: 72ch; }
.dshsec-kv--detail .dshsec-kv-row { grid-template-columns: minmax(90px, 140px) minmax(0, 1fr); }
.dshsec-review { display: grid; gap: 6px; }
.dshsec-review-verdict { font-size: 13.5px; }
.dshsec-path { list-style: none; margin: 0; padding: 0; display: grid; gap: 16px; }
.dshsec-path-step { display: grid; gap: 8px; min-width: 0; }
.dshsec-path-text { display: flex; gap: 10px; align-items: baseline; min-width: 0; }
.dshsec-path-text > p { min-width: 0; }
.dshsec-path-n {
  flex: none; display: inline-flex; align-items: center; justify-content: center; width: 20px; height: 20px;
  border-radius: 50%; background: var(--dshsec-fill-strong); color: var(--dshsec-text2); font-size: 12px; font-weight: 500;
}
.dshsec-path-step.is-unverified, .dshsec-evidence li.is-unverified {
  padding: 8px 10px; margin-left: -10px; border-radius: 8px; background: var(--dshsec-warn-tint);
}
.dshsec-evidence { list-style: none; margin: 0; padding: 0; display: grid; gap: 14px; }
.dshsec-evidence li { display: grid; gap: 8px; min-width: 0; }
.dshsec-evidence-claim { display: grid; gap: 2px; }
.dshsec-evidence-source { font-size: 12px; }
.dshsec-code { margin: 0; border-radius: 10px; overflow: hidden; border: 1px solid var(--dshsec-line); background: var(--dshsec-code-bg); min-width: 0; }
.dshsec-code-path {
  display: flex; justify-content: space-between; align-items: center; gap: 4px 12px; flex-wrap: wrap;
  font-family: var(--dshsec-mono); font-size: 11.5px; color: var(--dshsec-text3);
  padding: 5px 12px; border-bottom: 1px solid var(--dshsec-line); overflow-wrap: anywhere;
}
.dshsec-code-path .dshsec-quote { font-family: inherit; font-size: 11.5px; }
.dshsec-code pre { margin: 0; padding: 8px 0; font-family: var(--dshsec-mono); font-size: 12.5px; line-height: 1.6; tab-size: 2; }
.dshsec-code code { display: block; }
/* Long lines wrap under their own text; the line number column stays put. */
.dshsec-code-line { display: grid; grid-template-columns: auto minmax(0, 1fr); padding-right: 12px; }
.dshsec-code-ln {
  padding: 0 10px 0 12px; margin-right: 12px; color: var(--dshsec-text3);
  border-right: 1px solid var(--dshsec-line); user-select: none; text-align: right; white-space: pre;
}
.dshsec-code-src { white-space: pre-wrap; overflow-wrap: anywhere; min-width: 0; }
.dshsec-recheck { display: flex; align-items: center; gap: 6px 12px; flex-wrap: wrap; }
.dshsec-recheck .dshsec-hint { flex: 1 1 260px; }
.dshsec-triage { gap: 12px; }
.dshsec-triage .dshsec-fieldset > legend { margin-bottom: 4px; }
.dshsec-segmented { display: flex; flex-wrap: wrap; gap: 6px; }
.dshsec-seg {
  position: relative; display: inline-flex; align-items: center; height: 30px; padding: 0 12px; border-radius: 8px;
  border: 1px solid var(--dshsec-line-strong); cursor: pointer; font-size: 13px;
}
.dshsec-seg:hover { background: var(--dshsec-fill); }
.dshsec-seg input { position: absolute; opacity: 0; pointer-events: none; }
.dshsec-seg.is-selected { border-color: var(--dshsec-text); box-shadow: inset 0 0 0 1px var(--dshsec-text); font-weight: 500; }
.dshsec-seg:has(input:focus-visible) { outline: 2px solid var(--dshsec-focus); outline-offset: 2px; }
.dshsec-refs { display: grid; gap: 10px; padding-top: 18px; border-top: 1px solid var(--dshsec-line); }
.dshsec-refs-list { font-size: 13px; }

.dshsec-history .dshsec-table td { vertical-align: middle; }
.dshsec-history tr.is-viewing td { background: var(--dshsec-fill); }
.dshsec-row-actions { display: flex; gap: 6px; justify-content: flex-end; flex-wrap: wrap; padding-right: 0 !important; }
.dshsec-counts { display: inline-flex; gap: 2px 12px; flex-wrap: wrap; }
.dshsec-counts .dshsec-count { margin-left: 0; font-size: 13px; display: inline-flex; align-items: center; gap: 6px; font-variant-numeric: tabular-nums; }
.dshsec-dirty { color: var(--dshsec-warn-ink); margin-left: 2px; }
@container dshsec-page (max-width: 680px) {
  .dshsec-history thead { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
  .dshsec-history tr { display: grid; grid-template-columns: 1fr 1fr; gap: 6px 12px; padding: 12px 0; border-bottom: 1px solid var(--dshsec-line); }
  .dshsec-history td { border: 0; padding: 0; display: block; }
  .dshsec-history td[data-label]::before { content: attr(data-label); display: block; font-size: 11.5px; color: var(--dshsec-text3); }
  .dshsec-history .dshsec-row-actions { grid-column: 1 / -1; justify-content: flex-start; padding-top: 4px; display: flex; }
}
`

const settings = /* css */ `
.dshsec-settings-host { display: grid; gap: 16px; --dshsec-bg: var(--dsw-alias-bg-layer-2, #ffffff); --dshsec-card: var(--dshsec-bg); }
.dshsec-settings-intro { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.dshsec-settings { display: grid; gap: 0; container-type: inline-size; }
.dshsec-sgroup { display: grid; gap: 14px; padding: 24px 0; border-top: 1px solid var(--dshsec-line); }
.dshsec-sgroup:first-child { border-top: 0; padding-top: 0; }
.dshsec-sgroup-head { display: grid; gap: 4px; align-content: start; }
.dshsec-sgroup-title { font-size: 15px; line-height: 22px; font-weight: 500; }
.dshsec-sgroup-head .dshsec-muted { font-size: 13px; line-height: 1.6; }
.dshsec-sgroup-body { display: grid; gap: 18px; min-width: 0; }
@container (min-width: 760px) {
  .dshsec-sgroup { grid-template-columns: 200px minmax(0, 1fr); gap: 32px; }
}
.dshsec-grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 18px; }
.dshsec-roles { display: grid; gap: 0; }
.dshsec-role {
  display: grid; grid-template-columns: minmax(0, 1fr) minmax(220px, 300px); gap: 8px 20px; align-items: start;
  padding: 14px 0; border-top: 1px solid var(--dshsec-line); min-width: 0;
}
.dshsec-role:first-child { border-top: 0; padding-top: 0; }
.dshsec-role-text { display: grid; gap: 2px; min-width: 0; }
.dshsec-role-control { display: grid; gap: 8px; min-width: 0; }
.dshsec-role-control .dshsec-select { display: flex; }
.dshsec-role.is-inherited .dshsec-select select { color: var(--dshsec-text2); }
@container (max-width: 520px) { .dshsec-role { grid-template-columns: minmax(0, 1fr); } }
.dshsec-budgets { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 20px; }
.dshsec-budget { border: 0; margin: 0; padding: 0; display: grid; gap: 10px; min-width: 0; align-content: start; }
.dshsec-budget > legend { padding: 0; margin-bottom: 6px; }
.dshsec-budget .dshsec-input--num { max-width: none; }
.dshsec-role-name { font-weight: 500; font-size: 14px; }
.dshsec-analyzers { list-style: none; margin: 0; padding: 0; display: grid; gap: 6px; }
.dshsec-analyzers li { display: flex; align-items: baseline; gap: 8px; flex-wrap: wrap; }
.dshsec-analyzer-name { font-weight: 500; }
.dshsec-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; align-self: center; }
.dshsec-dot.is-on { background: var(--dshsec-ok); }
.dshsec-dot.is-off { background: var(--dshsec-line-strong); }
.dshsec-tools { list-style: none; margin: 0; padding: 0; display: grid; gap: 0; }
.dshsec-tool { display: grid; gap: 6px; padding: 12px 0; border-bottom: 1px solid var(--dshsec-line); min-width: 0; }
.dshsec-tool:first-child { padding-top: 4px; }
.dshsec-tool:last-child { border-bottom: 0; }
.dshsec-tool-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.dshsec-tool-meta { display: flex; gap: 4px 14px; flex-wrap: wrap; font-size: 12.5px; }
.dshsec-tool-install { display: grid; gap: 8px; padding: 10px 12px; border-radius: 10px; background: var(--dshsec-fill); }
.dshsec-install-hint { white-space: pre-wrap; overflow-wrap: anywhere; }
.dshsec-facts { margin: 0; display: flex; flex-wrap: wrap; gap: 8px 32px; }
.dshsec-facts > div { display: grid; gap: 2px; min-width: 0; }
.dshsec-facts dt { font-size: 12.5px; color: var(--dshsec-text3); }
.dshsec-facts dd { margin: 0; overflow-wrap: anywhere; }
.dshsec-link-icon { display: inline-flex; align-items: center; gap: 4px; }
.dshsec-copyline { display: grid; gap: 4px; min-width: 0; }
.dshsec-copyline-label { font-size: 12.5px; color: var(--dshsec-text2); }
.dshsec-copyline-row {
  display: flex; align-items: center; gap: 8px; min-width: 0;
  padding: 6px 6px 6px 12px; border-radius: 8px; background: var(--dshsec-code-bg); border: 1px solid var(--dshsec-line);
}
.dshsec-copyline-code { flex: 1 1 auto; min-width: 0; overflow-wrap: anywhere; user-select: all; }
.dshsec-copyline-row .dshsec-btn { flex: none; }
.dshsec-savebar {
  position: sticky; bottom: 0; z-index: 5; display: flex; align-items: center; justify-content: space-between;
  gap: 8px 12px; flex-wrap: wrap; padding: 12px 0; margin-top: 8px;
  background: var(--dshsec-bg); border-top: 1px solid var(--dshsec-line-strong);
  /* The second shadow paints the host scroller's bottom padding so content never shows below the bar. */
  box-shadow: 0 -12px 16px -12px rgba(0, 0, 0, 0.18), 0 28px 0 0 var(--dshsec-bg);
}
.dshsec-savebar-text { color: var(--dshsec-text2); font-size: 13px; min-width: 0; }
.dshsec-savebar-text.is-error { color: var(--dshsec-err-ink); }
.dshsec-savebar-actions { display: flex; gap: 8px; margin-left: auto; }
`

const motion = /* css */ `
@media (prefers-reduced-motion: reduce) {
  .dshsec-root *, .dshsec-root *::before, .dshsec-root *::after {
    animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important;
  }
  .dshsec-spinner, .dshsec-btn[aria-busy='true']::before { animation: none !important; }
}
@media (forced-colors: active) {
  .dshsec-frow.is-selected, .dshsec-tab[aria-selected='true'], .dshsec-mode.is-selected { outline: 2px solid CanvasText; }
  .dshsec-meter > span { background: Highlight; }
}
`

const directory = `
.dshsec-directory-list { list-style: none; padding: 0; margin: 0; max-height: 35vh; overflow: auto; }
.dshsec-directory-list .dshsec-btn { justify-content: flex-start; width: 100%; min-width: 0; white-space: normal; overflow-wrap: anywhere; text-align: left; }
.dshsec-directory-crumbs .dshsec-btn { max-width: 100%; min-width: 0; white-space: normal; overflow-wrap: anywhere; text-align: left; }
`

export const STYLES = [tokens, frame, controls, modal, overview, findings, settings, motion, directory].join('\n')

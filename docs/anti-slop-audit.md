# Anti-Slop Existing UI Audit

Audit mode: AFTER. Scope: current main workspace, Overview, Visualize, Analyze, Migration, Review, validation, empty/error states, controls, technical copy, comments, and narrow layouts. Direction: [`DESIGN.md`](../DESIGN.md).

## Findings

1. **AS-001**
   - **Location:** Main workspace introduction, `app/templates/index.html`
   - **Rule/category:** Copy; unsupported claims
   - **Current problem:** “Equivalent candidate configuration” implies semantic equivalence that application-level conversion cannot guarantee.
   - **Why it matters:** Engineers could read the phrase as stronger assurance than the product provides.
   - **Proposed correction:** Describe generated output as a candidate configuration requiring engineer review.
   - **Severity:** IMPORTANT

2. **AS-002**
   - **Location:** Main workspace introduction, `app/templates/index.html` and `app/static/css/app.css`
   - **Rule/category:** UI hierarchy; product workspace versus marketing hero
   - **Current problem:** A centered, oversized introduction delays the configuration input and reads like a generic landing-page hero.
   - **Why it matters:** Configuration input is the primary workbench action, not a marketing conversion point.
   - **Proposed correction:** Use a compact, left-aligned workspace heading with restrained spacing.
   - **Severity:** MINOR

3. **AS-003**
   - **Location:** All links, buttons, form controls, and configuration editor
   - **Rule/category:** Accessibility; keyboard focus
   - **Current problem:** The stylesheet removes the textarea outline and defines no consistent visible `:focus-visible` state.
   - **Why it matters:** Keyboard users cannot reliably identify the active control.
   - **Proposed correction:** Add a high-contrast focus ring to every interactive control and restore an editor focus indicator.
   - **Severity:** IMPORTANT

4. **AS-004**
   - **Location:** Source Configuration upload control
   - **Rule/category:** Accessibility; keyboard operation
   - **Current problem:** The native file input is `display:none`; its label cannot receive keyboard focus or activation.
   - **Why it matters:** Keyboard-only users cannot upload a configuration file.
   - **Proposed correction:** Visually hide the native input while keeping it focusable; show focus on its label.
   - **Severity:** IMPORTANT

5. **AS-005**
   - **Location:** Vendor selectors, editors, result tabs, graph workspace, migration mapping rows
   - **Rule/category:** Responsive layout; reflow and overflow
   - **Current problem:** Several desktop grids and fixed-width controls lack complete narrow-screen reflow. Result tabs can compress or overflow unpredictably; five-column mapping rows become unusable.
   - **Why it matters:** Tablet and narrow-desktop users can lose readable controls and mapping context.
   - **Proposed correction:** Stack editors and graph details, reflow vendor controls, make tabs intentionally scrollable, and convert mapping rows to a narrow one-column layout.
   - **Severity:** IMPORTANT

6. **AS-006**
   - **Location:** Analyze submission and dynamic graph/migration/review requests
   - **Rule/category:** Human states; error recovery
   - **Current problem:** Some failed requests return generic text or no visible error. The analyze adapter inserts server error bodies without a dedicated recovery state.
   - **Why it matters:** Users may not know what failed or what action can recover their work.
   - **Proposed correction:** Add consistent inline errors with the failed operation and retry guidance. Preserve entered configuration.
   - **Severity:** IMPORTANT

7. **AS-007**
   - **Location:** Overview summary and analysis summary
   - **Rule/category:** UI; repeated statistic cards
   - **Current problem:** Entity and finding counts use repeated card tiles, including a nested second card row after analysis.
   - **Why it matters:** The pattern resembles a generic KPI dashboard and consumes space that could support denser engineering data.
   - **Proposed correction:** Replace with a compact definition list or table during a later structural UI pass.
   - **Severity:** MINOR

8. **AS-008**
   - **Location:** Result navigation and Review interaction
   - **Rule/category:** Accessibility; tab and selection semantics
   - **Current problem:** View buttons look like tabs but expose no tab roles, `aria-selected`, panel relationships, or selected review-item state.
   - **Why it matters:** Assistive technology receives weak navigation and selection context.
   - **Proposed correction:** Implement complete tab semantics and review selection state together with keyboard behavior, without changing existing selectors.
   - **Severity:** IMPORTANT

## Applied in this phase

AS-001 through AS-005 receive narrow, low-risk corrections. AS-006 and AS-008 were resolved during Phase J with coordinated request recovery, complete tab keyboard/ARIA behavior, and review selection state. AS-007 remains deferred to avoid an unrequested Overview redesign.

## Code comments

No application comment or docstring was removed. Existing comments explain security constraints, parser behavior, vendored licensing, or non-obvious topology and migration decisions; no generic narrative comment was found.
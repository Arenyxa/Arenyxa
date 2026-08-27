# Arenyxa V6.5.1 Navigation & Startup Hotfix

## Scope

V6.5.1 is a focused corrective release on top of the V6.5 workflow-integration baseline. It does not change the Dataset/Lineage/Workflow data model or migration contract.

## Fixed defects

1. **Navigation selection exclusivity**
   - Every page destination is now registered in one explicit `QButtonGroup` with `exclusive=True`.
   - The visual checked state is synchronized only to the last committed route.
   - Rejected navigation restores the prior selection.
   - Page-construction failures restore the prior selection before propagating the error.
   - Clicking the already selected page cannot leave the rail with zero selected destinations.

2. **Intelligence Studio startup import**
   - `PageHeader` is imported from `arenyxa.presentation.widgets`, where it is defined.
   - The invalid import from `arenyxa.presentation.pages.base` was removed.

3. **Repair Center radio-group ownership**
   - Automatic/manual repair mode now keeps its `QButtonGroup` as a dialog member and explicitly enables exclusivity.

4. **Navigation visual state**
   - Checked page text uses the normal foreground token while the accent is reserved for the selected background/left indicator.
   - Hover styling is explicit for navigation destinations.

5. **Integrity artifacts**
   - Source repair seed, repair manifest and source manifest are regenerated after the hotfix so a legitimate V6.5.1 source tree is not reported as modified V6.5.0 content.

## Regression protection

- Added an internal `from ... import ...` contract test to catch missing exported names such as the V6.5.0 `PageHeader` regression.
- Added page-ID uniqueness and literal route validation.
- Added a static contract requiring the exclusive navigation button group.
- Added an offscreen Qt UI test that checks one-and-only-one selected page across navigation transitions when PySide6 is available.

## Audit result

The selection audit also reviewed other persistent-selection controls:

- Settings checkboxes: intentional independent multi-selection.
- Repair category checkboxes: intentional manual multi-selection.
- Data Revision list: intentional extended selection because comparison requires two revisions.
- Network event table: already explicit single-selection.
- QTabWidget surfaces: single active tab by Qt design.

No additional unintended page-style multi-selection mechanism was found in the reviewed source tree.

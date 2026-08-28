# V9.1 Validation

Static validation targets:
- 12 narrative scenes retained
- Digital Earth assets retained
- Earth node focus logic retained
- RoundedBoxGeometry + RoomEnvironment integrated
- Flagship instrument + explodable Capture server integrated
- 8 language menu entries present
- no-scene-words CSS defense retained
- JS module and Node server syntax checked before packaging

Browser note: Three.js remains loaded from the same jsDelivr ESM source used by the V9.0 baseline.

## Local HTTP validation

PASS — `/` returned HTTP 200 with `text/html`.

PASS — `/assets/earth_surface.png` returned HTTP 200 with `image/png`.

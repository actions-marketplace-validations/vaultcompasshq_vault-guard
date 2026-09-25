// Just enough tar to read one file out of an npm tarball.
//
// Why this exists rather than a dependency: the dogfood harness has to run with
// nothing installed that this repository would not otherwise install, and
// reaching for a third-party extractor to open a tarball is exactly the kind of
// install-time code a secret scanner's own tooling should not add. A tar entry
// is a 512-byte header followed by its content rounded up to the next 512
// bytes, which is forty lines of arithmetic, so the arithmetic is here.
//
// Nothing is written to disk from the archive. The single entry the caller asks
// for is returned as a Buffer, and the caller parses it.

const { gunzipSync } = require('zlib');

const BLOCK = 512;

function readString(block, offset, length) {
  let end = offset;
  const limit = offset + length;
  while (end < limit && block[end] !== 0) {
    end += 1;
  }
  return block.toString('utf8', offset, end);
}

// Sizes are octal ASCII in a twelve byte field. The GNU base-256 extension
// exists for files above eight gigabytes, which no npm tarball entry is, so an
// unparseable size is treated as a malformed archive rather than something to
// guess at.
function readOctal(block, offset, length) {
  const text = readString(block, offset, length).trim();
  if (text.length === 0) return 0;
  const value = Number.parseInt(text, 8);
  if (!Number.isFinite(value) || value < 0) {
    throw new Error('tarball has an unreadable entry size');
  }
  return value;
}

function* tarEntries(bytes) {
  let offset = 0;
  while (offset + BLOCK <= bytes.length) {
    const header = bytes.subarray(offset, offset + BLOCK);
    const name = readString(header, 0, 100);
    if (name.length === 0) {
      // Two zero blocks end the archive; one is enough to stop reading.
      return;
    }
    const size = readOctal(header, 124, 12);
    const prefix = readString(header, 345, 155);
    const entryPath = prefix.length > 0 ? `${prefix}/${name}` : name;
    const start = offset + BLOCK;
    const end = start + size;
    if (end > bytes.length) {
      throw new Error(`tarball entry ${entryPath} runs past the end of the archive`);
    }
    yield { path: entryPath, content: bytes.subarray(start, end) };
    offset = start + Math.ceil(size / BLOCK) * BLOCK;
  }
}

function readTarballEntry(gzipped, wantedPath) {
  const bytes = gunzipSync(gzipped);
  for (const entry of tarEntries(bytes)) {
    if (entry.path === wantedPath) return entry.content;
  }
  return null;
}

module.exports = { readTarballEntry, tarEntries };

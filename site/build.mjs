import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const siteRoot = path.join(root, "site");
const distRoot = path.join(siteRoot, "dist");

const pages = [
  {
    slug: "",
    title: "Stitch Documentation",
    nav: "Home",
    source: path.join(siteRoot, "pages", "index.md"),
    group: "Start",
    description: "Fast offline Windows Event Log analysis from the command line.",
  },
  {
    slug: "about",
    title: "About",
    nav: "About",
    source: path.join(siteRoot, "pages", "about.md"),
    group: "Start",
    description: "What Stitch is built for and where it fits.",
  },
  {
    slug: "getting-started",
    title: "Getting Started",
    nav: "Getting Started",
    source: path.join(siteRoot, "pages", "getting-started.md"),
    group: "Start",
    description: "Build Stitch, point it at EVTX data, and run the first commands.",
  },
  {
    slug: "faq",
    title: "FAQs",
    nav: "FAQs",
    source: path.join(siteRoot, "pages", "faq.md"),
    group: "Start",
    description: "Common behavior and support questions.",
  },
  {
    slug: "basics",
    title: "Basics",
    nav: "Basics",
    source: path.join(siteRoot, "pages", "basics.md"),
    group: "Reference",
    description: "Input discovery, output modes, parallelism, and command behavior.",
  },
  {
    slug: "stql",
    title: "STQL",
    nav: "STQL",
    source: path.join(root, "docs", "stql.md"),
    group: "Reference",
    description: "Search syntax, operators, functions, and projections.",
  },
  {
    slug: "sigma",
    title: "Sigma",
    nav: "Sigma",
    source: path.join(root, "docs", "sigma.md"),
    group: "Reference",
    description: "Supported Sigma rule syntax, mappings, and correlation behavior.",
  },
  {
    slug: "output",
    title: "Output",
    nav: "Output",
    source: path.join(root, "docs", "output.md"),
    group: "Reference",
    description: "Pretty tables, JSONL, JSON, CSV, and correlation rendering.",
  },
  {
    slug: "dump",
    title: "Dump",
    nav: "Dump",
    source: path.join(root, "docs", "dump.md"),
    group: "Reference",
    description: "Record serialization and projected exports.",
  },
  {
    slug: "performance",
    title: "Performance",
    nav: "Performance",
    source: path.join(root, "docs", "performance.md"),
    group: "Operations",
    description: "Benchmark commands, Rayon notes, and memory tradeoffs.",
  },
];

const pageBySlug = new Map(pages.map((page) => [page.slug, page]));

await build();

async function build() {
  await rm(distRoot, { force: true, recursive: true });
  await mkdir(distRoot, { recursive: true });
  await copyFile(path.join(siteRoot, "styles.css"), path.join(distRoot, "styles.css"));
  await copyFile(path.join(siteRoot, "favicon.svg"), path.join(distRoot, "favicon.svg"));

  for (const page of pages) {
    const markdown = await readFile(page.source, "utf8");
    const rendered = renderMarkdown(markdown);
    const html = renderLayout(page, rendered);
    const outDir = page.slug ? path.join(distRoot, page.slug) : distRoot;
    await mkdir(outDir, { recursive: true });
    await writeFile(path.join(outDir, "index.html"), html);
  }
}

function renderLayout(page, rendered) {
  const title = page.slug ? `${page.title} | Stitch Docs` : "Stitch Documentation";
  const description = page.description;

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)}</title>
  <meta name="description" content="${escapeHtml(description)}">
  <link rel="icon" type="image/svg+xml" href="/favicon.svg">
  <link rel="stylesheet" href="/styles.css">
</head>
<body>
  <header class="topbar">
    <a class="brand" href="/">
      <span class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
        </svg>
      </span>
      <span>
        <strong>Stitch</strong>
        <small>EVTX docs</small>
      </span>
    </a>
    <nav class="topnav" aria-label="Primary">
      <a href="/getting-started/"${activeAttr(page.slug, "getting-started")}>Getting Started</a>
      <a href="/stql/"${activeAttr(page.slug, "stql")}>STQL</a>
      <a href="/sigma/"${activeAttr(page.slug, "sigma")}>Sigma</a>
      <a href="https://github.com/import-pandas-as-numpy/stitch">GitHub</a>
    </nav>
  </header>
  <div class="shell">
    <aside class="sidebar" aria-label="Documentation navigation">
      ${renderSidebar(page, rendered.toc)}
    </aside>
    <main class="doc">
      <div class="page-kicker">${escapeHtml(page.group)}</div>
      ${rendered.html}
    </main>
    <aside class="toc" aria-label="On this page">
      ${renderToc(rendered.toc)}
    </aside>
  </div>
  <footer class="footer">
    <p>Generated from repository docs. Built for <code>stitch.sudorem.dev</code>.</p>
  </footer>
</body>
</html>
`;
}

function renderSidebar(currentPage, currentToc) {
  const groups = [];
  for (const page of pages) {
    let group = groups.find((candidate) => candidate.name === page.group);
    if (!group) {
      group = { name: page.group, pages: [] };
      groups.push(group);
    }
    group.pages.push(page);
  }

  return groups
    .map(
      (group) => `<section class="nav-group">
  <h2>${escapeHtml(group.name)}</h2>
  ${group.pages.map((page) => renderSidebarLink(page, currentPage, currentToc)).join("\n  ")}
</section>`,
    )
    .join("\n");
}

function renderSidebarLink(page, currentPage, currentToc) {
  const href = page.slug ? `/${page.slug}/` : "/";
  const isCurrent = page.slug === currentPage.slug;
  const active = isCurrent ? ' aria-current="page"' : "";
  const sectionLinks = isCurrent ? renderSidebarSections(currentToc) : "";
  return `<div class="nav-item"><a href="${href}"${active}><span>${escapeHtml(page.nav)}</span><small>${escapeHtml(page.description)}</small></a>${sectionLinks}</div>`;
}

function renderSidebarSections(toc) {
  const sections = toc.filter((item) => item.level === 2);
  if (sections.length === 0) {
    return "";
  }

  return `<ol class="nav-sections">
${sections.map((item) => `<li><a href="#${item.id}">${escapeHtml(item.text)}</a></li>`).join("\n")}
</ol>`;
}

function renderToc(toc) {
  if (toc.length === 0) {
    return '<p class="toc-empty">No sections</p>';
  }
  return `<h2>On this page</h2>
<ol>
${toc
  .map((item) => `<li class="toc-${item.level}"><a href="#${item.id}">${escapeHtml(item.text)}</a></li>`)
  .join("\n")}
</ol>`;
}

function activeAttr(current, target) {
  return current === target ? ' aria-current="page"' : "";
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const toc = [];
  const html = [];
  const paragraph = [];
  let inCode = false;
  let codeLang = "";
  let codeLines = [];
  let listType = null;
  let listItemOpen = false;

  const flushParagraph = () => {
    if (paragraph.length > 0) {
      html.push(`<p>${renderInline(paragraph.join(" "))}</p>`);
      paragraph.length = 0;
    }
  };

  const closeList = () => {
    if (listType) {
      if (listItemOpen) {
        html.push("</li>");
        listItemOpen = false;
      }
      html.push(`</${listType}>`);
      listType = null;
    }
  };

  const closeBlocks = () => {
    flushParagraph();
    closeList();
  };

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const fence = line.match(/^```([A-Za-z0-9_-]*)\s*$/);
    if (fence) {
      if (inCode) {
        html.push(`<pre><code${codeLang ? ` class="language-${escapeAttr(codeLang)}"` : ""}>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
        inCode = false;
        codeLang = "";
        codeLines = [];
      } else {
        closeBlocks();
        inCode = true;
        codeLang = fence[1] ?? "";
      }
      continue;
    }

    if (inCode) {
      codeLines.push(line);
      continue;
    }

    if (line.trim() === "") {
      closeBlocks();
      continue;
    }

    const table = readTable(lines, index);
    if (table) {
      closeBlocks();
      html.push(renderTable(table));
      index += table.linesConsumed - 1;
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      closeBlocks();
      const level = heading[1].length;
      const text = stripInline(heading[2].trim());
      const id = uniqueId(slugify(text), toc);
      if (level === 2 || level === 3) {
        toc.push({ id, level, text });
      }
      html.push(`<h${level} id="${id}"><a class="anchor" href="#${id}" aria-hidden="true">#</a>${renderInline(heading[2].trim())}</h${level}>`);
      continue;
    }

    const unordered = line.match(/^\s*[-*]\s+(.+)$/);
    const ordered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (unordered || ordered) {
      flushParagraph();
      const nextType = ordered ? "ol" : "ul";
      if (listType && listType !== nextType) {
        closeList();
      }
      if (!listType) {
        listType = nextType;
        html.push(`<${listType}>`);
      }
      if (listItemOpen) {
        html.push("</li>");
      }
      html.push(`<li>${renderInline((unordered ?? ordered)[1])}`);
      listItemOpen = true;
      continue;
    }

    if (listType && listItemOpen) {
      html.push(`<br>${renderInline(line.trim())}`);
      continue;
    }

    paragraph.push(line.trim());
  }

  closeBlocks();
  if (inCode) {
    html.push(`<pre><code${codeLang ? ` class="language-${escapeAttr(codeLang)}"` : ""}>${escapeHtml(codeLines.join("\n"))}</code></pre>`);
  }

  return { html: html.join("\n"), toc };
}

function readTable(lines, start) {
  const header = lines[start];
  const delimiter = lines[start + 1] ?? "";
  if (!isTableRow(header) || !/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(delimiter)) {
    return null;
  }

  const rows = [header, delimiter];
  let cursor = start + 2;
  while (cursor < lines.length && isTableRow(lines[cursor])) {
    rows.push(lines[cursor]);
    cursor += 1;
  }

  return { rows, linesConsumed: rows.length };
}

function renderTable(table) {
  const [header, , ...body] = table.rows.map(splitTableRow);
  return `<div class="table-wrap"><table>
<thead><tr>${header.map((cell) => `<th>${renderInline(cell)}</th>`).join("")}</tr></thead>
<tbody>
${body.map((row) => `<tr>${row.map((cell) => `<td>${renderInline(cell)}</td>`).join("")}</tr>`).join("\n")}
</tbody>
</table></div>`;
}

function splitTableRow(row) {
  return row
    .trim()
    .replace(/^\|/, "")
    .replace(/\|$/, "")
    .split("|")
    .map((cell) => cell.trim());
}

function isTableRow(line) {
  return /^\s*\|.+\|\s*$/.test(line);
}

function renderInline(value) {
  const code = [];
  let text = value.replace(/`([^`]+)`/g, (_, snippet) => {
    const key = `\u0000CODE${code.length}\u0000`;
    code.push(`<code>${escapeHtml(snippet)}</code>`);
    return key;
  });

  text = escapeHtml(text)
    .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, label, href) => {
      const safeHref = sanitizeHref(href);
      return `<a href="${escapeAttr(safeHref)}">${label}</a>`;
    });

  for (const [index, snippet] of code.entries()) {
    text = text.replace(`\u0000CODE${index}\u0000`, snippet);
  }
  return text;
}

function stripInline(value) {
  return value
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1");
}

function sanitizeHref(href) {
  if (/^(https?:|mailto:|#|\/)/.test(href)) {
    return href;
  }
  const [hrefPath, fragment] = href.split("#", 2);
  if (hrefPath.endsWith(".md")) {
    const slug = path.basename(hrefPath, ".md");
    if (pageBySlug.has(slug)) {
      return fragment ? `/${slug}/#${fragment}` : `/${slug}/`;
    }
  }
  if (/^[A-Za-z0-9._~/-]+(#[A-Za-z0-9._~-]+)?$/.test(href)) {
    return href;
  }
  return "#";
}

function uniqueId(base, toc) {
  const candidate = base || "section";
  const seen = new Set(toc.map((item) => item.id));
  if (!seen.has(candidate)) {
    return candidate;
  }
  let suffix = 2;
  while (seen.has(`${candidate}-${suffix}`)) {
    suffix += 1;
  }
  return `${candidate}-${suffix}`;
}

function slugify(value) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, "")
    .trim()
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/'/g, "&#39;");
}

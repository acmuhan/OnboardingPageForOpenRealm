(function () {
  "use strict";

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/\"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function sanitizeMarkdownUrl(rawUrl) {
    if (typeof rawUrl !== "string") {
      return null;
    }
    const cleaned = rawUrl.trim();
    if (!cleaned) {
      return null;
    }

    try {
      const parsed = new URL(cleaned, window.location.href);
      const allowed = new Set(["http:", "https:", "mailto:", "tel:"]);
      return allowed.has(parsed.protocol) ? parsed.href : null;
    } catch (error) {
      return null;
    }
  }

  function renderInline(rawText) {
    const text = String(rawText || "");
    const pattern = /(\[([^\]]+)\]\(([^)]+)\)|\*\*([^*]+)\*\*)/g;
    let html = "";
    let lastIndex = 0;
    let match;

    while ((match = pattern.exec(text)) !== null) {
      html += escapeHtml(text.slice(lastIndex, match.index));

      if (match[2] !== undefined && match[3] !== undefined) {
        const safeHref = sanitizeMarkdownUrl(match[3]);
        if (safeHref) {
          html += '<a href="' + escapeHtml(safeHref) + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(match[2]) + "</a>";
        } else {
          html += escapeHtml(match[0]);
        }
      } else if (match[4] !== undefined) {
        html += "<strong>" + escapeHtml(match[4]) + "</strong>";
      } else {
        html += escapeHtml(match[0]);
      }

      lastIndex = pattern.lastIndex;
    }

    html += escapeHtml(text.slice(lastIndex));
    return html;
  }

  function flushParagraph(buffer, output) {
    if (!buffer.length) {
      return;
    }
    const merged = buffer.map(renderInline).join("<br>");
    output.push("<p>" + merged + "</p>");
    buffer.length = 0;
  }

  function renderLimitedMarkdown(markdown) {
    const text = String(markdown || "");
    const lines = text.replace(/\r\n/g, "\n").split("\n");
    const output = [];
    const paragraph = [];
    let inList = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (!line) {
        flushParagraph(paragraph, output);
        if (inList) {
          output.push("</ul>");
          inList = false;
        }
        continue;
      }

      const headingMatch = line.match(/^(#{1,6})\s+(.+)$/);
      if (headingMatch) {
        flushParagraph(paragraph, output);
        if (inList) {
          output.push("</ul>");
          inList = false;
        }
        const level = headingMatch[1].length;
        output.push("<h" + level + ">" + renderInline(headingMatch[2]) + "</h" + level + ">");
        continue;
      }

      const listMatch = line.match(/^[-*+]\s+(.+)$/);
      if (listMatch) {
        flushParagraph(paragraph, output);
        if (!inList) {
          output.push("<ul>");
          inList = true;
        }
        output.push("<li>" + renderInline(listMatch[1]) + "</li>");
        continue;
      }

      if (inList) {
        output.push("</ul>");
        inList = false;
      }
      paragraph.push(line);
    }

    flushParagraph(paragraph, output);
    if (inList) {
      output.push("</ul>");
    }

    return output.join("");
  }

  function renderPlainText(text) {
    return escapeHtml(String(text || "")).replace(/\n/g, "<br>");
  }

  window.MarkdownRenderer = {
    escapeHtml,
    renderLimitedMarkdown,
    renderPlainText,
  };
})();

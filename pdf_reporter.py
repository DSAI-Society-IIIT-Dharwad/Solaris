"""
pdf_reporter.py
───────────────
Professional security audit PDF for shadowtracerv1.
Mirrors the terminal Kill Chain Report section-for-section.

Sections
  Cover page
  Section 1 — Attack Path Detection   (all paths, sorted ascending by risk)
  Section 2 — Blast Radius Analysis   (BFS per source)
  Section 3 — Circular Permission Detection
  Section 4 — Critical Node Analysis
  Summary block
  Section 5 — Remediation Roadmap
  BONUS — Temporal Analysis

Fonts: 100% built-in PDF fonts (Helvetica family + Courier).
       No external font files required — works inside Docker.
"""

import os
from datetime import datetime

import networkx as nx

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable, KeepTogether, PageBreak, Paragraph,
    SimpleDocTemplate, Spacer, Table, TableStyle,
)
from reportlab.platypus.flowables import Flowable

from config import REMEDIATION_MAP

# ═══════════════════════════════════════════════════════════════
# PALETTE  — calm, professional, easy on the eyes
# ═══════════════════════════════════════════════════════════════
INK         = colors.HexColor('#1c2333')
NAVY        = colors.HexColor('#1e3a5f')
STEEL       = colors.HexColor('#2c4a6e')
CYAN        = colors.HexColor('#1a8fa0')
SILVER      = colors.HexColor('#dce3ed')
GHOST       = colors.HexColor('#f2f5f9')
WHITE       = colors.white

SEV_CRITICAL = colors.HexColor('#c0392b')
SEV_HIGH     = colors.HexColor('#d35400')
SEV_MEDIUM   = colors.HexColor('#b7770d')
SEV_LOW      = colors.HexColor('#1e8449')

BG_CRITICAL  = colors.HexColor('#fdecea')
BG_HIGH      = colors.HexColor('#fef0e6')
BG_MEDIUM    = colors.HexColor('#fefae6')
BG_LOW       = colors.HexColor('#eafaf1')

CROWN_RED    = colors.HexColor('#922b21')
REC_BG       = colors.HexColor('#eaf4fb')
REC_BORDER   = colors.HexColor('#2980b9')

PAGE_W, PAGE_H = letter
BODY_W = PAGE_W - 1.5 * inch


# ═══════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════

def _sev(score):
    if score >= 15: return "CRITICAL"
    if score >= 8:  return "HIGH"
    if score >= 4:  return "MEDIUM"
    return "LOW"


def _sev_ink(sev):
    return {"CRITICAL": SEV_CRITICAL, "HIGH": SEV_HIGH,
            "MEDIUM":   SEV_MEDIUM,   "LOW":  SEV_LOW}.get(sev, SEV_LOW)


def _sev_bg(sev):
    return {"CRITICAL": BG_CRITICAL, "HIGH": BG_HIGH,
            "MEDIUM":   BG_MEDIUM,   "LOW":  BG_LOW}.get(sev, GHOST)


def _bar(value, maximum, width=22):
    if maximum == 0:
        return ""
    filled = int(round(value / maximum * width))
    return "█" * filled + "░" * (width - filled)


def _node_label(nid, G):
    d     = G.nodes.get(nid, {})
    name  = d.get('name', nid.split(':')[-1] if ':' in nid else nid)
    ntype = d.get('type', '')
    return name, ntype


def _edge_rel(u, v, G):
    ed = G[u][v] if G.has_edge(u, v) else {}
    return ed.get('relationship', ed.get('relation', '?'))


# ═══════════════════════════════════════════════════════════════
# CUSTOM FLOWABLE — coloured left-border panel
# ═══════════════════════════════════════════════════════════════

class LeftBorderPanel(Flowable):
    """Draws a solid coloured left accent bar beside a block of content."""

    def __init__(self, inner_flowables, bar_color=NAVY, bg_color=GHOST,
                 bar_width=4, padding=10, width=None):
        super().__init__()
        self._inner    = inner_flowables
        self._bar_c    = bar_color
        self._bg_c     = bg_color
        self._bar_w    = bar_width
        self._pad      = padding
        self._width    = width or BODY_W

    def wrap(self, availW, availH):
        inner_w = self._width - self._bar_w - self._pad * 2
        self._items = []
        total_h = self._pad
        for f in self._inner:
            w, h = f.wrap(inner_w, availH)
            self._items.append((f, h))
            total_h += h + 2
        total_h += self._pad
        self._total_h = total_h
        return (self._width, total_h)

    def draw(self):
        c = self.canv
        c.setFillColor(self._bg_c)
        c.rect(0, 0, self._width, self._total_h, fill=1, stroke=0)
        c.setFillColor(self._bar_c)
        c.rect(0, 0, self._bar_w, self._total_h, fill=1, stroke=0)
        y = self._total_h - self._pad
        x = self._bar_w + self._pad
        for (f, h) in self._items:
            y -= h
            f.drawOn(c, x, y)
            y -= 2


# ═══════════════════════════════════════════════════════════════
# STYLE SHEET
# ═══════════════════════════════════════════════════════════════

def _styles():
    def ps(name, font='Helvetica', size=9, leading=None, color=INK,
           align=TA_LEFT, sb=0, sa=0, **kw):
        return ParagraphStyle(
            name, fontName=font, fontSize=size,
            leading=leading or round(size * 1.45),
            textColor=color, alignment=align,
            spaceBefore=sb, spaceAfter=sa, **kw)

    S = {}
    # Cover
    S['c_title']   = ps('c_title',   'Helvetica-Bold',   30, color=WHITE,  align=TA_CENTER, leading=36)
    S['c_sub']     = ps('c_sub',     'Helvetica',        13, color=SILVER, align=TA_CENTER)
    S['c_meta']    = ps('c_meta',    'Helvetica',         9, color=SILVER, align=TA_CENTER)
    S['c_tagline'] = ps('c_tagline', 'Helvetica-Oblique', 8,
                        color=colors.HexColor('#7fb3d3'), align=TA_CENTER)
    # Stat tiles
    S['t_num']     = ps('t_num',     'Helvetica-Bold',   20, color=NAVY,   align=TA_CENTER, leading=24)
    S['t_lbl']     = ps('t_lbl',     'Helvetica',         7, color=STEEL,  align=TA_CENTER, leading=10)
    # Banner / headings
    S['banner']    = ps('banner',    'Helvetica-Bold',   10, color=WHITE,  leading=14)
    S['h3']        = ps('h3',        'Helvetica-Bold',    9, color=STEEL,  sb=6, sa=2)
    # Body
    S['body']      = ps('body',      'Helvetica',         9, color=INK,    leading=13)
    S['body_b']    = ps('body_b',    'Helvetica-Bold',    9, color=INK,    leading=13)
    S['body_sm']   = ps('body_sm',   'Helvetica',         8, color=INK,    leading=11)
    S['label']     = ps('label',     'Helvetica-Bold',    8, color=STEEL,  leading=11)
    S['mono']      = ps('mono',      'Courier',           8, color=INK,    leading=11)
    S['mono_c']    = ps('mono_c',    'Courier-Bold',      8, color=CYAN,   leading=11)
    # Path cards
    S['p_hdr']     = ps('p_hdr',     'Helvetica-Bold',    9, color=INK,    leading=13)
    S['p_node']    = ps('p_node',    'Helvetica-Bold',    9, color=NAVY,   leading=13)
    S['p_crown']   = ps('p_crown',   'Helvetica-Bold',    9, color=CROWN_RED, leading=13)
    S['p_rel']     = ps('p_rel',     'Courier-Bold',      8, color=CYAN,   leading=11)
    # Recommendation
    S['rec_t']     = ps('rec_t',     'Helvetica-Bold',    9, color=NAVY,   leading=13)
    S['rec_b']     = ps('rec_b',     'Helvetica',         9, color=STEEL,  leading=13)
    # Summary footer
    S['sum_l']     = ps('sum_l',     'Helvetica',         9, color=SILVER, leading=13)
    S['sum_v']     = ps('sum_v',     'Helvetica-Bold',    9, color=WHITE,  leading=13)
    return S


# ═══════════════════════════════════════════════════════════════
# BUILDING BLOCKS
# ═══════════════════════════════════════════════════════════════

def _banner(text, S):
    t = Table([[Paragraph(text, S['banner'])]], colWidths=[BODY_W])
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), NAVY),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
    ]))
    return t


def _thin_rule(color=SILVER):
    return HRFlowable(width='100%', thickness=0.5, color=color,
                      spaceAfter=3, spaceBefore=0)


# ═══════════════════════════════════════════════════════════════
# PAGE HEADER / FOOTER
# ═══════════════════════════════════════════════════════════════

def _on_page(canvas, doc):
    canvas.saveState()
    w, h = letter

    # top rule
    canvas.setStrokeColor(NAVY)
    canvas.setLineWidth(1.5)
    canvas.line(0.75*inch, h - 0.44*inch, w - 0.75*inch, h - 0.44*inch)
    # header left
    canvas.setFont('Helvetica-Bold', 7.5)
    canvas.setFillColor(NAVY)
    canvas.drawString(0.75*inch, h - 0.37*inch,
                      "shadowtracerv1  |  Kubernetes Security Audit")
    # header right
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(STEEL)
    canvas.drawRightString(w - 0.75*inch, h - 0.37*inch,
                           datetime.now().strftime('%Y-%m-%d %H:%M'))
    # bottom rule
    canvas.setStrokeColor(SILVER)
    canvas.setLineWidth(0.5)
    canvas.line(0.75*inch, 0.44*inch, w - 0.75*inch, 0.44*inch)
    # page number
    canvas.setFont('Helvetica', 7.5)
    canvas.setFillColor(STEEL)
    canvas.drawCentredString(w / 2, 0.28*inch, f"Page {doc.page}")
    canvas.drawString(0.75*inch, 0.28*inch,
                      "CONFIDENTIAL — Authorised personnel only")
    canvas.restoreState()


# ═══════════════════════════════════════════════════════════════
# COVER PAGE
# ═══════════════════════════════════════════════════════════════

def _cover(story, S, stats):
    # Hero block
    hero = Table([
        [Paragraph("KUBERNETES CLUSTER", S['c_title'])],
        [Paragraph("SECURITY AUDIT REPORT", S['c_title'])],
        [Spacer(1, 6)],
        [Paragraph("Automated Attack Path &amp; Risk Analysis", S['c_sub'])],
        [Spacer(1, 4)],
        [Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            f"  &nbsp;|&nbsp;  Cluster: live-cluster",
            S['c_meta'])],
    ], colWidths=[BODY_W])
    hero.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), NAVY),
        ('TOPPADDING',    (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
    ]))
    story.append(hero)
    story.append(Spacer(1, 0.2*inch))

    # Stat tiles
    total, critical, high, medium = (
        stats['total'], stats['critical'], stats['high'], stats['medium'])
    nodes, edges = stats['nodes'], stats['edges']

    def _tile(lbl, val, c=NAVY):
        ns = ParagraphStyle('tn', parent=S['t_num'], textColor=c)
        return [Paragraph(str(val), ns), Paragraph(lbl, S['t_lbl'])]

    tw = BODY_W / 6
    tiles = Table([[
        Table([_tile("Total Paths",  total,    NAVY)],        colWidths=[tw]),
        Table([_tile("Critical",     critical, SEV_CRITICAL)],colWidths=[tw]),
        Table([_tile("High",         high,     SEV_HIGH)],    colWidths=[tw]),
        Table([_tile("Medium",       medium,   SEV_MEDIUM)],  colWidths=[tw]),
        Table([_tile("Nodes",        nodes,    STEEL)],       colWidths=[tw]),
        Table([_tile("Edges",        edges,    STEEL)],       colWidths=[tw]),
    ]], colWidths=[tw]*6)
    tiles.setStyle(TableStyle([
        ('BOX',           (0, 0), (-1, -1), 1,   SILVER),
        ('INNERGRID',     (0, 0), (-1, -1), 0.5, SILVER),
        ('BACKGROUND',    (0, 0), (-1, -1), GHOST),
        ('TOPPADDING',    (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('ALIGN',         (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(tiles)
    story.append(Spacer(1, 0.13*inch))

    # Status badge
    vuln     = total > 0
    s_text   = "CLUSTER STATUS:  VULNERABLE" if vuln else "CLUSTER STATUS:  SECURE"
    s_ink    = SEV_CRITICAL if vuln else SEV_LOW
    s_bg     = BG_CRITICAL  if vuln else BG_LOW
    sb_style = ParagraphStyle('cs', parent=S['body_b'],
                              textColor=s_ink, fontSize=10, alignment=TA_CENTER)
    sb = Table([[Paragraph(s_text, sb_style)]], colWidths=[BODY_W])
    sb.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), s_bg),
        ('TOPPADDING',    (0, 0), (-1, -1), 7),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 7),
        ('BOX',           (0, 0), (-1, -1), 1, s_ink),
    ]))
    story.append(sb)
    story.append(Spacer(1, 0.10*inch))
    story.append(Paragraph(
        "BFS Blast Radius  ·  Dijkstra Shortest Path  ·  "
        "DFS Cycle Detection  ·  Critical Node Analysis",
        S['c_tagline']))
    story.append(Spacer(1, 0.22*inch))


# ═══════════════════════════════════════════════════════════════
# SECTION 1 — ATTACK PATH DETECTION
# ═══════════════════════════════════════════════════════════════

def _path_card(idx, p_data, graph_ref, S):
    G     = graph_ref.G
    score = p_data.get('total_risk_score', 0)
    hops  = p_data.get('total_hops', 0)
    sev   = _sev(score)
    sev_c = _sev_ink(sev)
    sev_b = _sev_bg(sev)
    path  = p_data['path']

    # Header row
    hdr_s = ParagraphStyle('ph', parent=S['p_hdr'], textColor=sev_c)
    bdg_s = ParagraphStyle('pb', parent=S['label'],
                            textColor=sev_c, alignment=TA_CENTER)
    hdr_t = Table(
        [[Paragraph(
            f"Path #{idx}  |  {hops} hop{'s' if hops != 1 else ''}"
            f"  |  Risk Score: {score}",
            hdr_s),
          Paragraph(sev, bdg_s)]],
        colWidths=[BODY_W - 0.9*inch, 0.9*inch])
    hdr_t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), sev_b),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (0, 0),   8),
        ('RIGHTPADDING',  (1, 0), (1, 0),   8),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN',         (1, 0), (1, 0),   'CENTER'),
        ('BOX',           (0, 0), (-1, -1), 0.5, sev_c),
    ]))

    # Hop rows
    hop_rows = []
    for u, v in zip(path[:-1], path[1:]):
        u_name, u_type = _node_label(u, G)
        rel    = _edge_rel(u, v, G)
        u_data = G.nodes.get(u, {})
        cves   = u_data.get('cves', [])
        cve_str = ''
        if cves:
            cve_str = (f'  <font color="#d35400">'
                       f'[{cves[0]}  CVSS {u_data.get("risk_score", "")}]'
                       f'</font>')
        hop_rows.append([
            Paragraph(
                f'<b>{u_name}</b>  '
                f'<font color="#6c7a89">({u_type})</font>{cve_str}',
                S['body']),
            Paragraph(f'--[{rel}]--&gt;', S['p_rel']),
        ])

    # Crown jewel row
    l_name, l_type = _node_label(path[-1], G)
    hop_rows.append([
        Paragraph(
            f'<font color="#922b21"><b>{l_name}</b>'
            f'  ({l_type})  &lt;-- CROWN JEWEL</font>',
            S['p_crown']),
        Paragraph('', S['body']),
    ])

    hop_t = Table(hop_rows,
                  colWidths=[BODY_W * 0.60, BODY_W * 0.40])
    hop_t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), GHOST),
        ('TOPPADDING',    (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING',   (0, 0), (-1, -1), 10),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('LINEBELOW',     (0, 0), (-1, -2), 0.3, SILVER),
        ('BOX',           (0, 0), (-1, -1), 0.5, SILVER),
    ]))

    return KeepTogether([hdr_t, hop_t, Spacer(1, 0.09*inch)])


def _section1(story, S, all_paths, graph_ref):
    story.append(_banner(
        f"[ SECTION 1 — ATTACK PATH DETECTION (Dijkstra) ]"
        f"     {len(all_paths)} path(s) detected", S))
    story.append(Spacer(1, 0.09*inch))
    if not all_paths:
        story.append(Paragraph("No attack paths detected.", S['body']))
        return
    for idx, p in enumerate(all_paths, 1):
        story.append(_path_card(idx, p, graph_ref, S))


# ═══════════════════════════════════════════════════════════════
# SECTION 2 — BLAST RADIUS
# ═══════════════════════════════════════════════════════════════

def _section2(story, S, all_paths, graph_ref):
    story.append(PageBreak())
    story.append(_banner(
        "[ SECTION 2 — BLAST RADIUS ANALYSIS (BFS, depth=3) ]", S))
    story.append(Spacer(1, 0.09*inch))

    G = graph_ref.G
    sources = list({p['source']: True for p in all_paths}.keys())
    if not sources:
        sources = [n for n, a in G.nodes(data=True) if a.get('is_source')]

    hdr = [Paragraph(t, S['label']) for t in
           ['Source Node', 'Type', 'Reachable', 'Hop Breakdown']]
    rows = [hdr]
    for src in sources:
        lengths = nx.single_source_shortest_path_length(G, source=src, cutoff=3)
        by_hop  = {}
        for node, dist in lengths.items():
            if node != src and dist > 0:
                by_hop.setdefault(dist, []).append(node)
        total   = sum(len(v) for v in by_hop.values())
        s_name, s_type = _node_label(src, G)
        lines = [f"Hop {h}: {', '.join(_node_label(n,G)[0] for n in by_hop[h])}"
                 for h in sorted(by_hop)]
        rows.append([
            Paragraph(f'<b>{s_name}</b>', S['body']),
            Paragraph(s_type, S['body_sm']),
            Paragraph(str(total),
                      ParagraphStyle('rc', parent=S['body_b'],
                                     alignment=TA_CENTER,
                                     textColor=NAVY if total else STEEL)),
            Paragraph('\n'.join(lines) if lines else '—', S['mono']),
        ])

    cw = [BODY_W * r for r in [0.23, 0.15, 0.10, 0.52]]
    t = Table(rows, colWidths=cw, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  NAVY),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  WHITE),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  8),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [WHITE, GHOST]),
        ('GRID',          (0, 0), (-1, -1), 0.4, SILVER),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('ALIGN',         (2, 1), (2, -1),  'CENTER'),
    ]))
    story.append(t)


# ═══════════════════════════════════════════════════════════════
# SECTION 3 — CYCLE DETECTION
# ═══════════════════════════════════════════════════════════════

def _section3(story, S, graph_ref):
    story.append(Spacer(1, 0.18*inch))
    story.append(_banner(
        "[ SECTION 3 — CIRCULAR PERMISSION DETECTION (DFS) ]", S))
    story.append(Spacer(1, 0.09*inch))

    G      = graph_ref.G
    cycles = [c for c in nx.simple_cycles(G) if len(c) > 1]

    if not cycles:
        story.append(Paragraph("No circular permissions detected.", S['body']))
        return

    story.append(Paragraph(f"{len(cycles)} cycle(s) detected:", S['body_b']))
    story.append(Spacer(1, 0.04*inch))
    for i, cycle in enumerate(cycles, 1):
        names = [_node_label(n, G)[0] for n in cycle]
        chain = (' <font color="#1a8fa0">&#8596;</font> '.join(names)
                 + f' <font color="#1a8fa0">&#8596;</font> {names[0]}')
        story.append(Paragraph(f'<b>Cycle #{i}:</b>  {chain}', S['body']))


# ═══════════════════════════════════════════════════════════════
# SECTION 4 — CRITICAL NODE ANALYSIS
# ═══════════════════════════════════════════════════════════════

def _section4(story, S, graph_ref, all_paths):
    story.append(Spacer(1, 0.18*inch))
    story.append(_banner(
        "[ SECTION 4 — CRITICAL NODE ANALYSIS ]", S))
    story.append(Spacer(1, 0.09*inch))

    G            = graph_ref.G
    entry_points = graph_ref.get_entry_points()
    all_pods     = [n for n, d in G.nodes(data=True) if d.get('type') == 'Pod']
    crown_jewels = graph_ref.get_crown_jewels()
    all_sources  = list(
        set(p['source'] for p in all_paths) | set(entry_points) | set(all_pods))

    cr       = graph_ref.identify_critical_node(all_sources, crown_jewels)
    baseline = cr.get('total_paths', len(all_paths))

    story.append(Paragraph(
        f"Baseline attack paths: <b>{baseline}</b>", S['body']))
    story.append(Spacer(1, 0.07*inch))

    if 'node' not in cr:
        story.append(Paragraph(
            cr.get('message', 'No critical node found.'), S['body']))
        return

    # Recommendation panel
    panel = LeftBorderPanel(
        [Paragraph("RECOMMENDATION", S['rec_t']),
         Spacer(1, 3),
         Paragraph(cr.get('recommendation', ''), S['rec_b'])],
        bar_color=REC_BORDER, bg_color=REC_BG, width=BODY_W)
    story.append(panel)
    story.append(Spacer(1, 0.10*inch))

    # Top-5 table
    top5 = cr.get('top5', [])
    if not top5:
        return
    story.append(Paragraph("Top 5 highest-impact nodes to remove:", S['h3']))
    story.append(Spacer(1, 0.04*inch))

    max_red = top5[0][1] if top5 else 1
    hdr     = [Paragraph(t, S['label'])
               for t in ['Node', 'Type', 'Paths Removed', 'Impact Bar']]
    t5_rows = [hdr]
    for node_id, reduction, _ in top5:
        n_name, n_type = _node_label(node_id, G)
        pct = int(round(reduction / baseline * 100)) if baseline else 0
        t5_rows.append([
            Paragraph(f'<b>{n_name}</b>', S['body']),
            Paragraph(n_type, S['body_sm']),
            Paragraph(
                f'{reduction}  ({pct}%)',
                ParagraphStyle('rc2', parent=S['body_b'],
                               alignment=TA_CENTER, textColor=SEV_CRITICAL)),
            Paragraph(
                f'<font color="#1a8fa0" fontName="Courier">'
                f'{_bar(reduction, max_red, 22)}</font>',
                S['body']),
        ])

    cw = [BODY_W * r for r in [0.28, 0.18, 0.18, 0.36]]
    t5 = Table(t5_rows, colWidths=cw)
    t5.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  STEEL),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  WHITE),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  8),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [WHITE, GHOST]),
        ('GRID',          (0, 0), (-1, -1), 0.4, SILVER),
        ('VALIGN',        (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING',    (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('ALIGN',         (2, 1), (2, -1),  'CENTER'),
    ]))
    story.append(t5)


# ═══════════════════════════════════════════════════════════════
# SUMMARY BLOCK
# ═══════════════════════════════════════════════════════════════

def _summary(story, S, all_paths, graph_ref):
    story.append(Spacer(1, 0.20*inch))
    G          = graph_ref.G
    cycles     = [c for c in nx.simple_cycles(G) if len(c) > 1]
    entry_pts  = graph_ref.get_entry_points()
    all_pods   = [n for n, d in G.nodes(data=True) if d.get('type') == 'Pod']
    crown_jwls = graph_ref.get_crown_jewels()
    all_srcs   = list(
        set(p['source'] for p in all_paths) | set(entry_pts) | set(all_pods))
    cr         = graph_ref.identify_critical_node(all_srcs, crown_jwls)

    blast_nodes = set()
    for src in {p['source'] for p in all_paths}:
        ls = nx.single_source_shortest_path_length(G, source=src, cutoff=3)
        blast_nodes.update(n for n, d in ls.items() if n != src and d > 0)

    rows = [
        ["Attack paths found",        str(len(all_paths))],
        ["Circular permissions",       str(len(cycles))],
        ["Total blast-radius nodes",   str(len(blast_nodes))],
        ["Critical node to remove",    cr.get('node_name', '—')],
    ]
    tbl_rows = [[Paragraph(r[0], S['sum_l']), Paragraph(r[1], S['sum_v'])]
                for r in rows]
    st = Table(tbl_rows, colWidths=[BODY_W * 0.6, BODY_W * 0.4])
    st.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, -1), NAVY),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (0, -1),  12),
        ('LEFTPADDING',   (1, 0), (1, -1),  8),
        ('LINEBELOW',     (0, 0), (-1, -2), 0.4,
         colors.HexColor('#2c4a6e')),
    ]))
    story.append(st)


# ═══════════════════════════════════════════════════════════════
# SECTION 5 — REMEDIATION ROADMAP
# ═══════════════════════════════════════════════════════════════

def _section5(story, S, all_paths, graph_ref):
    story.append(PageBreak())
    story.append(_banner(
        "[ SECTION 5 — REMEDIATION ROADMAP ]", S))
    story.append(Spacer(1, 0.08*inch))
    story.append(Paragraph(
        "Mitigations for each vulnerability type detected across all attack paths. "
        "Apply in order of severity — Critical paths first.",
        S['body']))
    story.append(Spacer(1, 0.09*inch))

    G        = graph_ref.G
    detected = set()
    for p_data in all_paths:
        for u, v in zip(p_data['path'][:-1], p_data['path'][1:]):
            rel = G[u][v].get('relationship', G[u][v].get('relation', ''))
            if rel in REMEDIATION_MAP:
                detected.add(rel)

    if not detected:
        story.append(Paragraph(
            "No specific vulnerability types mapped to remediations.", S['body']))
        return

    hdr = [Paragraph('Vulnerability Type', S['label']),
           Paragraph('Recommended Action', S['label'])]
    rem_rows = [hdr]
    for vuln in sorted(detected):
        rem_rows.append([
            Paragraph(vuln.replace('-', ' ').title(), S['body_b']),
            Paragraph(REMEDIATION_MAP[vuln], S['body']),
        ])

    cw = [BODY_W * 0.25, BODY_W * 0.75]
    rt = Table(rem_rows, colWidths=cw, repeatRows=1)
    rt.setStyle(TableStyle([
        ('BACKGROUND',    (0, 0), (-1, 0),  NAVY),
        ('TEXTCOLOR',     (0, 0), (-1, 0),  WHITE),
        ('FONTNAME',      (0, 0), (-1, 0),  'Helvetica-Bold'),
        ('FONTSIZE',      (0, 0), (-1, 0),  8),
        ('ROWBACKGROUNDS',(0, 1), (-1, -1), [WHITE, GHOST]),
        ('GRID',          (0, 0), (-1, -1), 0.4, SILVER),
        ('VALIGN',        (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING',    (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING',   (0, 0), (-1, -1), 6),
        ('RIGHTPADDING',  (0, 0), (-1, -1), 6),
        ('FONTSIZE',      (0, 1), (-1, -1), 8),
        ('LEADING',       (0, 1), (-1, -1), 12),
    ]))
    story.append(rt)


# ═══════════════════════════════════════════════════════════════
# BONUS — TEMPORAL ANALYSIS
# ═══════════════════════════════════════════════════════════════

def _section_temporal(story, S, new_paths, is_first_run, graph_ref):
    story.append(Spacer(1, 0.18*inch))
    story.append(_banner(
        "[ BONUS: TEMPORAL ANALYSIS (State-Diffing Engine) ]", S))
    story.append(Spacer(1, 0.09*inch))

    if is_first_run:
        story.append(Paragraph(
            "<b>Result:</b> Initial baseline recorded. Future scans will detect new paths.", 
            S['body']))
    elif not new_paths:
        story.append(Paragraph(
            "<b>Result:</b> No changes detected since last scan. Cluster state is stable.", 
            S['body']))
    else:
        story.append(Paragraph(
            f"<font color='#c0392b'><b>ALERT: {len(new_paths)} NEW attack path(s) detected since last scan!</b></font>", 
            S['body']))
        story.append(Spacer(1, 0.09*inch))
        
        # Reuse your existing path card renderer for the new paths!
        for idx, p in enumerate(new_paths, 1):
            story.append(_path_card(idx, p, graph_ref, S))


# ═══════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def export_full_pdf_report(all_paths, graph_ref, new_paths=None, is_first_run=False, filename="Full_Security_Audit.pdf"):
    """
    Drop-in replacement — same signature as the original.
    Generates a professional, visually rich PDF that mirrors the
    terminal Kill Chain Report section-for-section.
    """
    report_dir = os.getenv('REPORT_PATH', '.')
    full_path  = os.path.join(report_dir, filename)

    doc = SimpleDocTemplate(
        full_path, pagesize=letter,
        leftMargin=0.75*inch, rightMargin=0.75*inch,
        topMargin=0.65*inch,  bottomMargin=0.60*inch,
    )

    S = _styles()
    G = graph_ref.G

    total    = len(all_paths)
    critical = sum(1 for p in all_paths if p.get('total_risk_score', 0) >= 15)
    high     = sum(1 for p in all_paths if 8  <= p.get('total_risk_score', 0) < 15)
    medium   = sum(1 for p in all_paths if 4  <= p.get('total_risk_score', 0) < 8)
    stats    = dict(total=total, critical=critical, high=high, medium=medium,
                    nodes=G.number_of_nodes(), edges=G.number_of_edges())

    story = []
    _cover(story, S, stats)
    _section1(story, S, all_paths, graph_ref)
    _section2(story, S, all_paths, graph_ref)
    _section3(story, S, graph_ref)
    _section4(story, S, graph_ref, all_paths)
    _summary(story, S, all_paths, graph_ref)
    _section5(story, S, all_paths, graph_ref)
    
    # Inject the new temporal section at the end
    _section_temporal(story, S, new_paths, is_first_run, graph_ref)

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    print(f"[+] Security Audit PDF exported to: {full_path}")
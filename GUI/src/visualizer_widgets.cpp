#include "visualizer_widgets.h"
#include "colours.h"
#include <QPainter>
#include <QMouseEvent>
#include <QWheelEvent>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QEasingCurve>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <sstream>
#include <iomanip>
#include "modern_ciphers.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif


// Standard English Letter Frequencies (A-Z)

static const double ENG_FREQ[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

// Helper to calculate Shannon entropy
static double calc_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    size_t counts[256] = {0};
    for (size_t i = 0; i < len; ++i) counts[data[i]]++;
    double entropy = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

// ─────────────────────────────────────────────────────────────────────────────
// FrequencyHistogram Widget
// ─────────────────────────────────────────────────────────────────────────────

FrequencyHistogram::FrequencyHistogram(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    m_freqs.resize(26, 0.0);
    m_startFreqs.resize(26, 0.0);
    m_targetFreqs.resize(26, 0.0);
    m_english.assign(ENG_FREQ, ENG_FREQ + 26);
    setMinimumHeight(160);
}

void FrequencyHistogram::setAnimFraction(double f) {
    m_animFraction = f;
    for (int i = 0; i < 26; ++i) {
        m_freqs[i] = m_startFreqs[i] + (m_targetFreqs[i] - m_startFreqs[i]) * f;
    }
    update();
}

void FrequencyHistogram::setData(const std::string &data) {
    // Save current display as start for animation
    m_startFreqs = m_freqs;
    m_targetFreqs.assign(26, 0.0);
    size_t letters_count = 0;
    for (unsigned char c : data) {
        if (c >= 'A' && c <= 'Z') {
            m_targetFreqs[c - 'A'] += 1.0;
            letters_count++;
        } else if (c >= 'a' && c <= 'z') {
            m_targetFreqs[c - 'a'] += 1.0;
            letters_count++;
        }
    }
    if (letters_count > 0) {
        for (int i = 0; i < 26; ++i) {
            m_targetFreqs[i] = (m_targetFreqs[i] * 100.0) / letters_count;
        }
    }

    auto *anim = new QPropertyAnimation(this, "animFraction", this);
    anim->setDuration(300);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void FrequencyHistogram::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    // Draw dark background
    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();
    int padding = 24;
    int chart_h = h - 2 * padding;
    int col_w = (w - 2 * padding) / 26;

    // Find max frequency to scale the chart
    double max_freq = 15.0; // default cap
    for (double f : m_freqs) if (f > max_freq) max_freq = f;

    // Draw thin gridlines
    painter.setPen(QPen(COL_BORDER, 1, Qt::DashLine));
    for (int y = 1; y <= 3; ++y) {
        int y_pos = padding + chart_h - (y * chart_h / 4);
        painter.drawLine(padding, y_pos, w - padding, y_pos);
        painter.drawText(padding - 20, y_pos + 4, QString::number(y * (int)max_freq / 4) + "%");
    }

    // Draw bars
    for (int i = 0; i < 26; ++i) {
        int x = padding + i * col_w;
        int bar_gap = 2;
        int bar_w = (col_w - bar_gap * 2) / 2;

        // English standard bar (translucent accent color)
        double eng_f = m_english[i];
        int eng_h = (eng_f / max_freq) * chart_h;
        int eng_y = padding + chart_h - eng_h;
        painter.fillRect(x + bar_gap, eng_y, bar_w, eng_h, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 100));

        // Data frequency bar (teal color)
        double dat_f = m_freqs[i];
        int dat_h = (dat_f / max_freq) * chart_h;
        int dat_y = padding + chart_h - dat_h;
        painter.fillRect(x + bar_gap + bar_w, dat_y, bar_w, dat_h, COL_OUTPUT);

        // Hover highlight
        if (i == m_hover_index) {
            painter.fillRect(x, padding, col_w, chart_h, QColor(255, 255, 255, 25));
        }

        // Draw bottom label
        painter.setPen(COL_TEXT_DIM);
        painter.setFont(QFont("Courier New", 8, QFont::Bold));
        painter.drawText(x + col_w / 4, h - padding + 12, QString((char)('A' + i)));
    }

    // Draw Tooltip
    if (m_hover_index >= 0 && m_hover_index < 26) {
        QString tip = QString("%1: Data %2% | English %3%")
                          .arg((char)('A' + m_hover_index))
                          .arg(m_freqs[m_hover_index], 0, 'f', 1)
                          .arg(m_english[m_hover_index], 0, 'f', 1);

        painter.setPen(COL_ACCENT_GL);
        painter.setBrush(COL_SURFACE2);
        int tip_w = 210;
        int tip_h = 24;
        int tip_x = std::clamp(padding + m_hover_index * col_w - tip_w / 2, 4, w - tip_w - 4);
        int tip_y = padding - 4;
        
        painter.drawRoundedRect(tip_x, tip_y, tip_w, tip_h, 4, 4);
        painter.setPen(COL_TEXT);
        painter.setFont(QFont("Courier New", 9));
        painter.drawText(tip_x + 6, tip_y + 16, tip);
    }
}

void FrequencyHistogram::mouseMoveEvent(QMouseEvent *event) {
    int padding = 24;
    int col_w = (width() - 2 * padding) / 26;
    if (col_w <= 0) return;
    int idx = (static_cast<int>(event->position().x()) - padding) / col_w;
    if (idx >= 0 && idx < 26) {
        if (idx != m_hover_index) {
            m_hover_index = idx;
            update();
        }
    } else {
        if (m_hover_index != -1) {
            m_hover_index = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EntropyHeatmap Widget
// ─────────────────────────────────────────────────────────────────────────────

EntropyHeatmap::EntropyHeatmap(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setMinimumHeight(150);
}

void EntropyHeatmap::setAnimFraction(double f) {
    m_animFraction = f;
    size_t n = std::min(m_startEntropy.size(), m_targetEntropy.size());
    m_block_entropy.resize(m_targetEntropy.size());
    for (size_t i = 0; i < n; ++i) {
        m_block_entropy[i] = m_startEntropy[i] + (m_targetEntropy[i] - m_startEntropy[i]) * f;
    }
    for (size_t i = n; i < m_targetEntropy.size(); ++i) {
        m_block_entropy[i] = m_targetEntropy[i];
    }
    update();
}

void EntropyHeatmap::setData(const std::string &data) {
    m_startEntropy = m_block_entropy;
    m_targetEntropy.clear();
    if (data.empty()) {
        m_block_entropy.clear();
        update();
        return;
    }

    size_t block_size = 16;
    if (data.size() > 1024) block_size = 64;
    if (data.size() > 8192) block_size = 256;

    for (size_t i = 0; i < data.size(); i += block_size) {
        size_t len = std::min(block_size, data.size() - i);
        double e = calc_entropy((const uint8_t*)data.data() + i, len);
        m_targetEntropy.push_back(e);
        if (m_targetEntropy.size() >= 256) break;
    }

    auto *anim = new QPropertyAnimation(this, "animFraction", this);
    anim->setDuration(300);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutCubic);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void EntropyHeatmap::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_block_entropy.empty()) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "No analysis data");
        return;
    }

    int n = (int)m_block_entropy.size();
    int cols = std::ceil(std::sqrt(n));
    if (cols < 4) cols = 4;
    int rows = (n + cols - 1) / cols;

    int cell_w = (width() - 10) / cols;
    int cell_h = (height() - 10) / rows;
    if (cell_w <= 0) cell_w = 4;
    if (cell_h <= 0) cell_h = 4;

    for (int i = 0; i < n; ++i) {
        int r = i / cols;
        int c = i % cols;
        int x = 5 + c * cell_w;
        int y = 5 + r * cell_h;

        double ent = m_block_entropy[i];
        // Scale to 0.0 - 8.0 max Shannon entropy
        double ratio = ent / 8.0;
        if (ratio > 1.0) ratio = 1.0;

        // Mix custom colors: Low (dark slate/purple) -> High (bright teal output color)
        int r_val = COL_SURFACE.red() + (COL_OUTPUT.red() - COL_SURFACE.red()) * ratio;
        int g_val = COL_SURFACE.green() + (COL_OUTPUT.green() - COL_SURFACE.green()) * ratio;
        int b_val = COL_SURFACE.blue() + (COL_OUTPUT.blue() - COL_SURFACE.blue()) * ratio;
        QColor color(r_val, g_val, b_val);

        painter.fillRect(x + 1, y + 1, cell_w - 2, cell_h - 2, color);

        // Highlights for hover
        if (c == m_hover_x && r == m_hover_y) {
            painter.setPen(QPen(COL_TEXT, 2));
            painter.drawRect(x, y, cell_w - 1, cell_h - 1);
        }
    }

    // Display hover value info
    if (m_hover_x >= 0 && m_hover_y >= 0) {
        int idx = m_hover_y * cols + m_hover_x;
        if (idx >= 0 && idx < n) {
            double ent = m_block_entropy[idx];
            QString msg = QString("Block #%1: Entropy %2").arg(idx + 1).arg(ent, 0, 'f', 2);
            painter.setPen(COL_ACCENT_GL);
            painter.fillRect(5, height() - 22, 180, 18, COL_SURFACE2);
            painter.drawText(8, height() - 8, msg);
        }
    }
}

void EntropyHeatmap::mouseMoveEvent(QMouseEvent *event) {
    if (m_block_entropy.empty()) return;
    int n = (int)m_block_entropy.size();
    int cols = std::ceil(std::sqrt(n));
    if (cols < 4) cols = 4;
    int rows = (n + cols - 1) / cols;

    int cell_w = (width() - 10) / cols;
    int cell_h = (height() - 10) / rows;
    if (cell_w <= 0 || cell_h <= 0) return;

    int cx = (static_cast<int>(event->position().x()) - 5) / cell_w;
    int cy = (static_cast<int>(event->position().y()) - 5) / cell_h;

    if (cx >= 0 && cx < cols && cy >= 0 && cy < rows && (cy * cols + cx) < n) {
        if (cx != m_hover_x || cy != m_hover_y) {
            m_hover_x = cx;
            m_hover_y = cy;
            update();
        }
    } else {
        if (m_hover_x != -1 || m_hover_y != -1) {
            m_hover_x = -1;
            m_hover_y = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ShannonEntropyGraph Widget
// ─────────────────────────────────────────────────────────────────────────────

ShannonEntropyGraph::ShannonEntropyGraph(QWidget *parent) : QWidget(parent) {
    setMinimumHeight(150);
}

void ShannonEntropyGraph::setDrawProgress(double p) {
    m_drawProgress = p;
    update();
}

void ShannonEntropyGraph::setData(const std::string &data) {
    m_rolling_entropy.clear();
    if (data.size() < 16) {
        update();
        return;
    }

    size_t win_sz = 16;
    if (data.size() > 500) win_sz = 64;
    size_t step = std::max((size_t)1, data.size() / 100);

    for (size_t i = 0; i + win_sz <= data.size(); i += step) {
        double ent = calc_entropy((const uint8_t*)data.data() + i, win_sz);
        m_rolling_entropy.push_back(ent);
    }

    m_drawProgress = 0.0;
    auto *anim = new QPropertyAnimation(this, "drawProgress", this);
    anim->setDuration(400);
    anim->setStartValue(0.0);
    anim->setEndValue(1.0);
    anim->setEasingCurve(QEasingCurve::OutSine);
    anim->start(QAbstractAnimation::DeleteWhenStopped);
}

void ShannonEntropyGraph::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_rolling_entropy.size() < 2) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "Insufficient data for rolling graph");
        return;
    }

    int w = width();
    int h = height();
    int pad = 20;

    int graph_w = w - 2 * pad;
    int graph_h = h - 2 * pad;

    // Draw Grid Lines (from 0.0 to 8.0 bits)
    painter.setPen(QPen(COL_BORDER, 1, Qt::DotLine));
    for (int i = 0; i <= 4; ++i) {
        int y = pad + graph_h - (i * graph_h / 4);
        painter.drawLine(pad, y, w - pad, y);
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(2, y + 4, QString::number(i * 2));
    }

    // Determine how many points to draw based on drawProgress
    size_t drawCount = std::max((size_t)2,
        (size_t)(m_drawProgress * m_rolling_entropy.size()));

    // Build the line path
    QPainterPath path;
    double step_x = (double)graph_w / (m_rolling_entropy.size() - 1);
    
    for (size_t i = 0; i < drawCount; ++i) {
        double ent = m_rolling_entropy[i];
        double x = pad + i * step_x;
        double y = pad + graph_h - (ent / 8.0 * graph_h);
        if (i == 0) path.moveTo(x, y);
        else path.lineTo(x, y);
    }

    // Extend last point to edge for clean fill
    if (drawCount > 0 && drawCount < m_rolling_entropy.size()) {
        double x = pad + (drawCount - 1) * step_x;
        double y = pad + graph_h - (m_rolling_entropy[drawCount - 1] / 8.0 * graph_h);
        path.lineTo(x + step_x * 0.5, y);
    }

    // Fill area under curve
    QPainterPath areaPath = path;
    double lastX = pad + std::min(drawCount, m_rolling_entropy.size() - 1) * step_x;
    areaPath.lineTo(lastX, pad + graph_h);
    areaPath.lineTo(pad, pad + graph_h);
    areaPath.closeSubpath();

    QLinearGradient areaGrad(0, pad, 0, pad + graph_h);
    areaGrad.setColorAt(0, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 100));
    areaGrad.setColorAt(1, QColor(COL_ACCENT.red(), COL_ACCENT.green(), COL_ACCENT.blue(), 0));
    painter.fillPath(areaPath, areaGrad);

    // Draw main line
    painter.setPen(QPen(COL_ACCENT_HI, 2));
    painter.drawPath(path);
}

// ─────────────────────────────────────────────────────────────────────────────
// EncodingWheel Widget
// ─────────────────────────────────────────────────────────────────────────────

EncodingWheel::EncodingWheel(QWidget *parent) : QWidget(parent) {
    setMinimumSize(220, 220);
}

void EncodingWheel::setValue(const std::string &input_text) {
    m_binary.clear();
    m_octal.clear();
    m_decimal.clear();
    m_hex.clear();
    m_base64.clear();

    if (input_text.empty()) {
        update();
        return;
    }

    // Take first 4 bytes of input text to perform visual conversion wheel
    uint64_t val = 0;
    for (size_t i = 0; i < std::min((size_t)4, input_text.size()); ++i) {
        val = (val << 8) | (unsigned char)input_text[i];
    }

    // Create string representations
    std::stringstream ss;
    // 1. Binary
    for (int i = 31; i >= 0; i--) ss << ((val >> i) & 1);
    m_binary = ss.str().substr(0, 16) + "...";
    
    // 2. Octal
    ss.str(""); ss << std::oct << val;
    m_octal = ss.str();

    // 3. Decimal
    ss.str(""); ss << val;
    m_decimal = ss.str();

    // 4. Hex
    ss.str(""); ss << std::hex << std::uppercase << val;
    m_hex = "0x" + ss.str();

    // 5. Base64
    m_base64 = base64url_encode(input_text.substr(0, std::min((size_t)8, input_text.size())));
    if (m_base64.size() > 8) m_base64 = m_base64.substr(0, 8) + "..";

    update();
}

void EncodingWheel::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();
    int cx = w / 2;
    int cy = h / 2;
    int radius = std::min(cx, cy) - 20;

    // Draw concentric rings
    painter.setPen(QPen(COL_BORDER, 2));
    painter.drawEllipse(cx - radius, cy - radius, radius * 2, radius * 2);
    painter.drawEllipse(cx - radius / 2, cy - radius / 2, radius, radius);

    // Draw division lines (5 sectors)
    painter.setPen(QPen(COL_BORDER_HI, 1));
    for (int i = 0; i < 5; ++i) {
        double angle = i * 2.0 * M_PI / 5.0 - M_PI / 2.0;
        painter.drawLine(cx, cy, cx + radius * cos(angle), cy + radius * sin(angle));
    }

    // Draw text values in sectors
    QString labels[5] = {"BIN", "OCT", "DEC", "HEX", "B64"};
    QString values[5] = {
        QString::fromStdString(m_binary),
        QString::fromStdString(m_octal),
        QString::fromStdString(m_decimal),
        QString::fromStdString(m_hex),
        QString::fromStdString(m_base64)
    };

    for (int i = 0; i < 5; ++i) {
        double mid_angle = (i + 0.5) * 2.0 * M_PI / 5.0 - M_PI / 2.0;
        int text_r = radius * 0.7;
        int tx = cx + text_r * cos(mid_angle);
        int ty = cy + text_r * sin(mid_angle);

        // Draw Sector Label
        painter.setPen(COL_ACCENT_GL);
        painter.setFont(QFont("Courier New", 9, QFont::Bold));
        painter.drawText(tx - 15, ty - 6, labels[i]);

        // Draw Value
        painter.setPen(COL_TEXT);
        painter.setFont(QFont("Courier New", 8));
        QString val = values[i].isEmpty() ? "---" : values[i];
        if (val.size() > 10) val = val.left(8) + "..";
        painter.drawText(tx - 24, ty + 8, val);

        // Highlight selected
        if (i == m_selected_wheel_sector) {
            painter.setPen(QPen(COL_OUTPUT, 2));
            painter.drawEllipse(tx - 30, ty - 15, 60, 30);
        }
    }

    // Center Hub
    painter.setBrush(COL_BG);
    painter.setPen(QPen(COL_OUTPUT, 2));
    painter.drawEllipse(cx - 24, cy - 24, 48, 48);
    painter.setPen(COL_OUTPUT);
    painter.drawText(cx - 14, cy + 5, "CORE");
}

void EncodingWheel::mousePressEvent(QMouseEvent *event) {
    int cx = width() / 2;
    int cy = height() / 2;
    int dx = static_cast<int>(event->position().x()) - cx;
    int dy = static_cast<int>(event->position().y()) - cy;
    double dist = sqrt(dx*dx + dy*dy);
    int radius = std::min(cx, cy) - 20;

    if (dist > 24 && dist < radius) {
        double angle = atan2(dy, dx) + M_PI / 2.0;
        if (angle < 0) angle += 2.0 * M_PI;
        int sector = (int)(angle / (2.0 * M_PI / 5.0)) % 5;
        m_selected_wheel_sector = sector;

        int radices[5] = {2, 8, 10, 16, 64};
        emit baseSelected(radices[sector]);
        update();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AutocorrelationGraph Widget
// ─────────────────────────────────────────────────────────────────────────────

AutocorrelationGraph::AutocorrelationGraph(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setMinimumHeight(140);
}

void AutocorrelationGraph::setData(const std::string &data) {
    m_autocorr.clear();
    m_hoverLag = -1;

    if (data.size() < 4) return;

    size_t n = data.size();
    m_maxLag = std::min((size_t)200, n / 2);

    // Pre-compute byte values as doubles for autocorrelation
    std::vector<double> vals(n);
    for (size_t i = 0; i < n; ++i)
        vals[i] = (unsigned char)data[i];

    // Compute autocorrelation at each lag
    double sumSq = 0.0;
    for (size_t i = 0; i < n; ++i) sumSq += vals[i] * vals[i];
    if (sumSq == 0.0) return;

    for (int lag = 1; lag <= m_maxLag; ++lag) {
        double sum = 0.0;
        size_t count = n - lag;
        for (size_t i = 0; i < count; ++i)
            sum += vals[i] * vals[i + lag];
        m_autocorr.push_back(sum / sumSq);
    }
    update();
}

void AutocorrelationGraph::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_autocorr.size() < 2) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "Periodicity data");
        return;
    }

    int w = width();
    int h = height();
    int pad = 24;
    int graph_w = w - 2 * pad;
    int graph_h = h - 2 * pad;

    // Grid lines
    painter.setPen(QPen(COL_BORDER, 1, Qt::DotLine));
    for (int i = 1; i <= 4; ++i) {
        int y = pad + graph_h - (i * graph_h / 4);
        painter.drawLine(pad, y, w - pad, y);
    }

    double bar_w = (double)graph_w / m_autocorr.size();

    for (size_t i = 0; i < m_autocorr.size(); ++i) {
        double val = m_autocorr[i];
        int bar_h = std::max(1, (int)(val * graph_h));
        int x = pad + i * bar_w;
        int y = pad + graph_h - bar_h;

        bool hovered = ((int)i == m_hoverLag);
        QColor color = hovered ? COL_ACCENT_HI : COL_ACCENT;
        color.setAlpha(hovered ? 220 : 140);
        painter.fillRect(x + 1, y, (int)bar_w - 2, bar_h, color);

        if (hovered) {
            painter.setPen(QPen(COL_TEXT, 1));
            painter.drawRect(x + 1, y, (int)bar_w - 2, bar_h);

            QString label = QString("Lag %1: %2").arg(i + 1).arg(val, 0, 'f', 3);
            painter.setPen(COL_ACCENT_GL);
            painter.fillRect(5, 2, 160, 18, COL_SURFACE2);
            painter.drawText(8, 15, label);
        }
    }

    // X-axis labels
    painter.setPen(COL_TEXT_DIM);
    painter.setFont(QFont("Courier New", 7));
    int labelStep = std::max(1, (int)m_autocorr.size() / 10);
    for (size_t i = 0; i < m_autocorr.size(); i += labelStep) {
        int x = pad + i * bar_w;
        painter.drawText(x - 6, h - 4, QString::number(i + 1));
    }
    painter.drawText(pad, h - 4, "1");
    painter.drawText(w - pad - 20, h - 4, QString::number(m_maxLag));
}

void AutocorrelationGraph::mouseMoveEvent(QMouseEvent *event) {
    if (m_autocorr.empty()) return;
    double bar_w = (double)(width() - 48) / m_autocorr.size();
    if (bar_w <= 0) return;
    int idx = (event->position().x() - 24) / bar_w;
    if (idx >= 0 && idx < (int)m_autocorr.size()) {
        if (idx != m_hoverLag) {
            m_hoverLag = idx;
            update();
        }
    } else {
        if (m_hoverLag != -1) {
            m_hoverLag = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// NGramHeatmap Widget
// ─────────────────────────────────────────────────────────────────────────────

NGramHeatmap::NGramHeatmap(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setMinimumSize(220, 220);
}

void NGramHeatmap::setData(const std::string &data) {
    memset(m_digram, 0, sizeof(m_digram));
    m_maxCount = 1.0;
    m_hoverR = m_hoverC = -1;

    size_t count = 0;
    for (size_t i = 0; i + 1 < data.size(); ++i) {
        unsigned char a = data[i];
        unsigned char b = data[i + 1];
        if ((a >= 'A' && a <= 'Z') || (a >= 'a' && a <= 'z')) {
            if ((b >= 'A' && b <= 'Z') || (b >= 'b' && b <= 'z')) {
                int ra = (a >= 'a') ? a - 'a' : a - 'A';
                int rb = (b >= 'a') ? b - 'a' : b - 'A';
                m_digram[ra][rb] += 1.0;
                count++;
            }
        }
    }
    if (count > 0) {
        for (int r = 0; r < 26; ++r)
            for (int c = 0; c < 26; ++c)
                if (m_digram[r][c] > m_maxCount) m_maxCount = m_digram[r][c];
    }
    update();
}

void NGramHeatmap::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();
    int pad = 16;
    int grid_w = w - 2 * pad;
    int grid_h = h - 2 * pad;
    int cell_w = grid_w / 26;
    int cell_h = grid_h / 26;
    if (cell_w < 3 || cell_h < 3) return;

    for (int r = 0; r < 26; ++r) {
        for (int c = 0; c < 26; ++c) {
            int x = pad + c * cell_w;
            int y = pad + r * cell_h;
            double ratio = m_digram[r][c] / m_maxCount;

            // Color from dark surface (low) to accent teal (high)
            int rv = COL_SURFACE.red() + (COL_OUTPUT.red() - COL_SURFACE.red()) * ratio;
            int gv = COL_SURFACE.green() + (COL_OUTPUT.green() - COL_SURFACE.green()) * ratio;
            int bv = COL_SURFACE.blue() + (COL_OUTPUT.blue() - COL_SURFACE.blue()) * ratio;
            painter.fillRect(x, y, cell_w - 1, cell_h - 1, QColor(rv, gv, bv));

            if (r == m_hoverR && c == m_hoverC) {
                painter.setPen(QPen(COL_TEXT, 2));
                painter.drawRect(x, y, cell_w - 1, cell_h - 1);
            }
        }
    }

    // Axis labels
    painter.setPen(COL_TEXT_DIM);
    painter.setFont(QFont("Courier New", 7));
    for (int i = 0; i < 26; ++i) {
        int x = pad + i * cell_w + cell_w / 2 - 3;
        int y = pad - 3;
        painter.drawText(x, y, QString(QChar('A' + i)));
        y = pad + i * cell_h + cell_h / 2 + 3;
        painter.drawText(2, y, QString(QChar('A' + i)));
    }

    // Hover tooltip
    if (m_hoverR >= 0 && m_hoverC >= 0) {
        QString tip = QString("%1%2: %3")
            .arg(QChar('A' + m_hoverC))
            .arg(QChar('A' + m_hoverR))
            .arg(m_digram[m_hoverR][m_hoverC], 0, 'f', 1);
        painter.setPen(COL_ACCENT_GL);
        painter.fillRect(w / 2 - 50, 2, 100, 18, COL_SURFACE2);
        painter.drawText(w / 2 - 44, 15, tip);
    }
}

void NGramHeatmap::mouseMoveEvent(QMouseEvent *event) {
    int pad = 16;
    int cell_w = (width() - 2 * pad) / 26;
    int cell_h = (height() - 2 * pad) / 26;
    if (cell_w <= 0 || cell_h <= 0) return;

    int c = (event->position().x() - pad) / cell_w;
    int r = (event->position().y() - pad) / cell_h;

    if (r >= 0 && r < 26 && c >= 0 && c < 26) {
        if (r != m_hoverR || c != m_hoverC) {
            m_hoverR = r; m_hoverC = c;
            update();
        }
    } else {
        if (m_hoverR != -1 || m_hoverC != -1) {
            m_hoverR = m_hoverC = -1;
            update();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HexDiffViewer Widget
// ─────────────────────────────────────────────────────────────────────────────

HexDiffViewer::HexDiffViewer(QWidget *parent) : QWidget(parent) {
    setFocusPolicy(Qt::StrongFocus);
    setMinimumHeight(120);
}

void HexDiffViewer::setData(const std::string &input, const std::string &output) {
    m_input = input;
    m_output = output;
    m_scrollOffset = 0;
    update();
}

void HexDiffViewer::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    int w = width();
    int h = height();

    int n = std::max(m_input.size(), m_output.size());
    if (n == 0) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "No data for diff");
        return;
    }

    int rows = (n + m_bytesPerRow - 1) / m_bytesPerRow;
    int row_h = 18;
    int pad = 8;
    int header_h = 20;

    // Column widths
    int offset_w = 70;
    int input_w = (w - 3 * pad - offset_w) / 2;
    int output_w = w - pad - offset_w - pad - input_w - pad;

    int x_offset = pad;
    int x_input = x_offset + offset_w + pad;
    int x_output = x_input + input_w + pad;

    // Header
    painter.setPen(COL_ACCENT);
    painter.setFont(QFont("Courier New", 8, QFont::Bold));
    painter.drawText(x_offset, header_h - 4, "OFFSET");
    painter.drawText(x_input, header_h - 4, "INPUT");
    painter.drawText(x_output, header_h - 4, "OUTPUT");

    // Separator line
    painter.setPen(QPen(COL_BORDER, 1));
    painter.drawLine(pad, header_h + 2, w - pad, header_h + 2);

    int visible_rows = (h - header_h - 8) / row_h;
    int max_row = std::max(0, rows - visible_rows);
    if (m_scrollOffset > max_row) m_scrollOffset = max_row;
    if (m_scrollOffset < 0) m_scrollOffset = 0;

    // Draw rows
    for (int r = 0; r < visible_rows && (r + m_scrollOffset) < rows; ++r) {
        int row = r + m_scrollOffset;
        int y = header_h + 6 + r * row_h;
        int start = row * m_bytesPerRow;

        // Offset label
        painter.setPen(COL_TEXT_DIM);
        painter.setFont(QFont("Courier New", 8));
        QString offsetStr = QString("0x%1").arg(start, 6, 16, QChar('0'));
        painter.drawText(x_offset, y + 12, offsetStr);

        for (int side = 0; side < 2; ++side) {
            const std::string &data = (side == 0) ? m_input : m_output;
            int base_x = (side == 0) ? x_input : x_output;
            int col_w = ((side == 0) ? input_w : output_w) / (m_bytesPerRow * 3);

            for (int b = 0; b < m_bytesPerRow; ++b) {
                int idx = start + b;
                int bx = base_x + b * col_w * 3;

                if (idx < (int)data.size()) {
                    unsigned char byte = data[idx];

                    // Color: matching bytes green, differing red
                    bool match = (idx < (int)m_input.size() && idx < (int)m_output.size()
                                  && m_input[idx] == m_output[idx]);
                    bool inBoth = (idx < (int)m_input.size() && idx < (int)m_output.size());
                    QColor bg;
                    if (!inBoth) bg = COL_TEXT_DEAD;
                    else if (match) bg = QColor(0, 60, 40, 120);
                    else bg = QColor(80, 20, 20, 120);

                    painter.fillRect(bx, y, col_w * 2 + 2, row_h - 2, bg);

                    painter.setPen(match ? COL_OUTPUT : COL_ACCENT_GL);
                    painter.drawText(bx + 1, y + 12,
                        QString("%1").arg(byte, 2, 16, QChar('0')));
                } else {
                    // Missing byte
                    painter.fillRect(bx, y, col_w * 2 + 2, row_h - 2, COL_BG);
                    painter.setPen(COL_TEXT_DEAD);
                    painter.drawText(bx + 1, y + 12, "..");
                }
            }
        }
    }

    // Scroll indicator
    if (max_row > 0) {
        double vis = (double)visible_rows / rows;
        double pos = (double)m_scrollOffset / rows;
        int bar_h = std::max(8, (int)(vis * h));
        int bar_y = pos * h;
        painter.fillRect(w - 6, bar_y, 4, bar_h, COL_BORDER_HI);
    }
}

void HexDiffViewer::wheelEvent(QWheelEvent *event) {
    int rows = (std::max(m_input.size(), m_output.size()) + m_bytesPerRow - 1) / m_bytesPerRow;
    int visible_rows = (height() - 20 - 8) / 18;
    int max_row = std::max(0, rows - visible_rows);

    int delta = event->angleDelta().y();
    m_scrollOffset -= delta / 120;
    if (m_scrollOffset > max_row) m_scrollOffset = max_row;
    if (m_scrollOffset < 0) m_scrollOffset = 0;
    update();
}

// ─────────────────────────────────────────────────────────────────────────────
// DataMiniMap Widget
// ─────────────────────────────────────────────────────────────────────────────

DataMiniMap::DataMiniMap(QWidget *parent) : QWidget(parent) {
    setFixedHeight(28);
    setCursor(Qt::PointingHandCursor);
}

void DataMiniMap::setData(const std::string &data) {
    m_data = data;
    update();
}

void DataMiniMap::setHighlight(double startFrac, double endFrac) {
    m_hlStart = startFrac;
    m_hlEnd = endFrac;
    update();
}

void DataMiniMap::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    int w = width();
    int h = height();

    painter.fillRect(rect(), COL_SURFACE2);

    if (m_data.empty()) {
        painter.setPen(COL_TEXT_DEAD);
        painter.drawText(rect(), Qt::AlignCenter, "No data");
        return;
    }

    // Draw byte intensity strip
    size_t n = m_data.size();
    for (int x = 0; x < w; ++x) {
        size_t idx = (size_t)x * n / std::max(1, w);
        if (idx >= n) break;
        unsigned char byte = m_data[idx];
        double intensity = byte / 255.0;
        int rv = 10 + (COL_OUTPUT.red() - 10) * intensity;
        int gv = 5 + (COL_OUTPUT.green() - 5) * intensity;
        int bv = 20 + (COL_OUTPUT.blue() - 20) * intensity;
        painter.setPen(QColor(rv, gv, bv));
        painter.drawPoint(x, h / 2);
        painter.drawPoint(x, h / 2 - 1);
        painter.drawPoint(x, h / 2 + 1);
    }

    // Highlight overlay for visible region
    int hl_x = m_hlStart * w;
    int hl_w = (m_hlEnd - m_hlStart) * w;
    painter.fillRect(hl_x, 1, hl_w, h - 2, QColor(74, 124, 255, 40));
    painter.setPen(QPen(COL_ACCENT, 1));
    painter.drawRect(hl_x, 1, hl_w, h - 2);
}

void DataMiniMap::mousePressEvent(QMouseEvent *event) {
    double frac = (double)event->position().x() / width();
    if (frac < 0.0) frac = 0.0;
    if (frac > 1.0) frac = 1.0;
    emit positionClicked(frac);
}

// ─────────────────────────────────────────────────────────────────────────────
// BlockCipherModeViz Widget
// ─────────────────────────────────────────────────────────────────────────────

BlockCipherModeViz::BlockCipherModeViz(QWidget *parent) : QWidget(parent) {
    setMouseTracking(true);
    setMinimumHeight(160);
}

void BlockCipherModeViz::setData(const std::string &data) {
    m_data = data;
    m_hoverBlock = -1;
    update();
}

// Simple hash of a byte buffer for color generation
static uint32_t block_hash(const uint8_t *data, size_t len) {
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x01000193;
    }
    return h;
}

// Map hash to a saturated color
static QColor hash_to_color(uint32_t hash) {
    int r = (hash >> 16) & 0xFF;
    int g = (hash >> 8) & 0xFF;
    int b = hash & 0xFF;
    // Boost saturation
    double avg = (r + g + b) / 3.0;
    r = std::min(255, (int)(avg + (r - avg) * 1.5));
    g = std::min(255, (int)(avg + (g - avg) * 1.5));
    b = std::min(255, (int)(avg + (b - avg) * 1.5));
    if (r < 0) r = 0;
    if (g < 0) g = 0;
    if (b < 0) b = 0;
    return QColor(r, g, b, 200);
}

void BlockCipherModeViz::paintEvent(QPaintEvent *event) {
    Q_UNUSED(event);
    QPainter painter(this);
    painter.setRenderHint(QPainter::Antialiasing);

    painter.fillRect(rect(), COL_SURFACE);

    if (m_data.size() < 16) {
        painter.setPen(COL_TEXT_DIM);
        painter.drawText(rect(), Qt::AlignCenter, "Need >= 16 bytes for block analysis");
        return;
    }

    int blockSize = 16;
    int numBlocks = m_data.size() / blockSize;
    int displayBlocks = std::min(numBlocks, 128);
    int cols = std::min(displayBlocks, 32);
    int rows = (displayBlocks + cols - 1) / cols;

    int panel_w = (width() - 12) / 2;
    int pad = 16;
    int cell_w = std::min((panel_w - pad) / cols, 20);
    int cell_h = std::min((height() - 40) / rows, 20);
    cell_w = std::max(4, cell_w);
    cell_h = std::max(4, cell_h);

    // Label
    painter.setPen(COL_ACCENT);
    painter.setFont(QFont("Courier New", 9, QFont::Bold));

    // Fixed seed for CBC-like avalanche simulation
    uint32_t cbc_state = 0x6f6243;

    for (int panel = 0; panel < 2; ++panel) {
        int base_x = 4 + panel * (panel_w + 4);
        bool isECB = (panel == 0);

        painter.drawText(base_x + pad, 12, isECB ? "ECB MODE" : "CBC MODE");

        for (int i = 0; i < displayBlocks && i < numBlocks; ++i) {
            int r = i / cols;
            int c = i % cols;
            int x = base_x + pad + c * cell_w;
            int y = 20 + r * cell_h;

            const uint8_t *block = (const uint8_t*)m_data.data() + i * blockSize;
            uint32_t color_seed;
            if (isECB) {
                // ECB: each block independently hashed
                color_seed = block_hash(block, blockSize);
            } else {
                // CBC: each block mixed with previous state
                cbc_state = block_hash(block, blockSize) ^ (cbc_state * 0x9e3779b9);
                color_seed = cbc_state;
            }

            QColor col = hash_to_color(color_seed);

            bool hovered = (m_hoverBlock == i && isECB);
            if (hovered) {
                painter.setPen(QPen(COL_TEXT, 2));
            } else {
                painter.setPen(Qt::NoPen);
            }
            painter.fillRect(x, y, cell_w - 1, cell_h - 1, col);
            if (hovered) painter.drawRect(x, y, cell_w - 1, cell_h - 1);
        }
    }

    // Tooltip
    if (m_hoverBlock >= 0 && m_hoverBlock < numBlocks) {
        QString tip = QString("Block %1: %2")
            .arg(m_hoverBlock)
            .arg(m_data.substr(m_hoverBlock * 16, 16).c_str());
        painter.setPen(COL_ACCENT_GL);
        painter.fillRect(width() / 2 - 100, height() - 22, 200, 18, COL_SURFACE2);
        painter.drawText(width() / 2 - 94, height() - 8, tip);
    }
}

void BlockCipherModeViz::mouseMoveEvent(QMouseEvent *event) {
    if (m_data.size() < 16) return;
    int panel_w = (width() - 12) / 2;
    int pad = 16;
    int numBlocks = m_data.size() / 16;
    int displayBlocks = std::min(numBlocks, 128);
    int cols = std::min(displayBlocks, 32);
    int rows = (displayBlocks + cols - 1) / cols;
    int cell_w = std::min((panel_w - pad) / cols, 20);
    int cell_h = std::min((height() - 40) / rows, 20);
    cell_w = std::max(4, cell_w);
    cell_h = std::max(4, cell_h);

    int mx = event->position().x();
    int my = event->position().y();

    // Check ECB panel (left side)
    if (mx >= 4 + pad && mx < 4 + pad + cols * cell_w && my >= 20 && my < 20 + rows * cell_h) {
        int col = (mx - 4 - pad) / cell_w;
        int row = (my - 20) / cell_h;
        int idx = row * cols + col;
        if (idx >= 0 && idx < displayBlocks) {
            if (idx != m_hoverBlock) {
                m_hoverBlock = idx;
                update();
            }
            return;
        }
    }
    if (m_hoverBlock != -1) {
        m_hoverBlock = -1;
        update();
    }
}

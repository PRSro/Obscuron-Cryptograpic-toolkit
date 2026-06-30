#ifndef VISUALIZER_WIDGETS_H
#define VISUALIZER_WIDGETS_H

#include <QWidget>
#include <QTimer>
#include <string>
#include <vector>

// 1. Character Frequency Histogram comparing current text with standard English
class FrequencyHistogram : public QWidget {
    Q_OBJECT
    Q_PROPERTY(double animFraction READ animFraction WRITE setAnimFraction)
public:
    explicit FrequencyHistogram(QWidget *parent = nullptr);
    void setData(const std::string &data);

    double animFraction() const { return m_animFraction; }
    void setAnimFraction(double f);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private:
    std::vector<double> m_freqs;      // Current display frequencies (A-Z)
    std::vector<double> m_startFreqs; // Start freqs for animation
    std::vector<double> m_targetFreqs;// Target frequencies (A-Z)
    std::vector<double> m_english;    // Standard English frequencies (A-Z)
    double m_animFraction = 1.0;
    int m_hover_index = -1;
};

// 2. Entropy Heatmap to visualize byte randomness
class EntropyHeatmap : public QWidget {
    Q_OBJECT
    Q_PROPERTY(double animFraction READ animFraction WRITE setAnimFraction)
public:
    explicit EntropyHeatmap(QWidget *parent = nullptr);
    void setData(const std::string &data);

    double animFraction() const { return m_animFraction; }
    void setAnimFraction(double f);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;

private:
    std::vector<double> m_block_entropy;    // Current display entropy
    std::vector<double> m_startEntropy;     // Start entropy for animation
    std::vector<double> m_targetEntropy;    // Target entropy values
    double m_animFraction = 1.0;
    int m_hover_x = -1;
    int m_hover_y = -1;
};

// 3. Shannon Entropy Graph: smooth line chart showing entropy over sliding window
class ShannonEntropyGraph : public QWidget {
    Q_OBJECT
    Q_PROPERTY(double drawProgress READ drawProgress WRITE setDrawProgress)
public:
    explicit ShannonEntropyGraph(QWidget *parent = nullptr);
    void setData(const std::string &data);

    double drawProgress() const { return m_drawProgress; }
    void setDrawProgress(double p);

protected:
    void paintEvent(QPaintEvent *event) override;

private:
    std::vector<double> m_rolling_entropy;
    double m_drawProgress = 1.0;
};

// 4. Interactive Encoding Wheel showing radix conversion
class EncodingWheel : public QWidget {
    Q_OBJECT
public:
    explicit EncodingWheel(QWidget *parent = nullptr);
    void setValue(const std::string &input_text);

signals:
    void baseSelected(int radix);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    std::string m_binary;
    std::string m_octal;
    std::string m_decimal;
    std::string m_hex;
    std::string m_base64;
    int m_selected_wheel_sector = -1;
};

// 5. Autocorrelation Graph for periodicity detection (Vigenere key length, etc.)
class AutocorrelationGraph : public QWidget {
    Q_OBJECT
public:
    explicit AutocorrelationGraph(QWidget *parent = nullptr);
    void setData(const std::string &data);
protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
private:
    std::vector<double> m_autocorr;
    int m_hoverLag = -1;
    int m_maxLag = 0;
};

// 6. N-Gram Heatmap (26x26 digram frequency matrix)
class NGramHeatmap : public QWidget {
    Q_OBJECT
public:
    explicit NGramHeatmap(QWidget *parent = nullptr);
    void setData(const std::string &data);
protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
private:
    double m_digram[26][26] = {{0}};
    int m_hoverR = -1, m_hoverC = -1;
    double m_maxCount = 1.0;
};

// 7. Hex Diff Viewer: side-by-side input vs output bytes with color coding
class HexDiffViewer : public QWidget {
    Q_OBJECT
public:
    explicit HexDiffViewer(QWidget *parent = nullptr);
    void setData(const std::string &input, const std::string &output);
    QSize minimumSizeHint() const override { return QSize(200, 120); }
protected:
    void paintEvent(QPaintEvent *event) override;
    void wheelEvent(QWheelEvent *event) override;
private:
    std::string m_input, m_output;
    int m_scrollOffset = 0;
    int m_bytesPerRow = 16;
};

// 8. Data Mini-Map: thin bar showing byte intensity across the data
class DataMiniMap : public QWidget {
    Q_OBJECT
public:
    explicit DataMiniMap(QWidget *parent = nullptr);
    void setData(const std::string &data);
    void setHighlight(double startFrac, double endFrac);
signals:
    void positionClicked(double fraction);
protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;
private:
    std::string m_data;
    double m_hlStart = 0.0, m_hlEnd = 1.0;
};

// 9. Block Cipher Mode Comparison: ECB vs CBC block pattern visualization
class BlockCipherModeViz : public QWidget {
    Q_OBJECT
public:
    explicit BlockCipherModeViz(QWidget *parent = nullptr);
    void setData(const std::string &data);
protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
private:
    std::string m_data;
    int m_hoverBlock = -1;
};

#endif // VISUALIZER_WIDGETS_H

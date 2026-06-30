#include "recipe_engine.h"
#include "recipe_model.h"
#include "plugin_loader.h"
#include "basic.h"
#include "detector.h"
#include "modern_ciphers.h"
#include <QElapsedTimer>
#include <QRegularExpression>
#include <QMutexLocker>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <sstream>

RecipeEngine::RecipeEngine(QObject *parent) : QObject(parent) {
    m_metrics.total_time_ms = 0.0;
    m_metrics.throughput_mbs = 0.0;
    m_metrics.memory_used_bytes = 0;
}

RecipeEngine::~RecipeEngine() {
    cancelAsync();
}

void RecipeEngine::runAsync(const std::string &input, const std::vector<RecipeStep> &steps) {
    cancelAsync();
    m_asyncSteps = steps;
    m_workerThread = QThread::create([this, input]() {
        QElapsedTimer timer;
        timer.start();
        std::string current_data = input;
        int steps_run = 0;
        int n = (int)m_asyncSteps.size();

        for (int i = 0; i < n; i++) {
            if (QThread::currentThread()->isInterruptionRequested())
                break;

            RecipeStep &step = m_asyncSteps[i];
            if (!step.enabled) {
                step.intermediate_output = current_data;
                step.has_error = false;
                step.error_message.clear();
                step.execution_time_ms = 0.0;
                emit executionProgress(i, n);
                continue;
            }

            QElapsedTimer step_timer;
            step_timer.start();

            bool success = true;
            std::string error_msg;
            std::string step_output = executeSingleStep(current_data, step, success, error_msg);

            double elapsed_step = step_timer.nsecsElapsed() / 1000000.0;
            step.execution_time_ms = elapsed_step;
            step.has_error = !success;
            step.error_message = error_msg;

            if (success) {
                current_data = step_output;
                step.intermediate_output = current_data;
                steps_run++;
                emit stepExecuted(i, true, elapsed_step);
            } else {
                step.intermediate_output = current_data;
                emit stepExecuted(i, false, elapsed_step);
                break;
            }
            emit executionProgress(i, n);
        }

        double total_ms = timer.nsecsElapsed() / 1000000.0;
        m_metrics.total_time_ms = total_ms;
        m_metrics.timestamp = QDateTime::currentDateTime();

        if (total_ms > 0) {
            double bytes = input.size() + current_data.size();
            m_metrics.throughput_mbs = (bytes / 1024.0 / 1024.0) / (total_ms / 1000.0);
        } else {
            m_metrics.throughput_mbs = 0;
        }
        m_metrics.memory_used_bytes = input.size() + current_data.size() + (steps_run * 1024);

        emit executionFinished(current_data, m_metrics);
    });

    connect(m_workerThread, &QThread::finished, m_workerThread, &QObject::deleteLater);
    m_workerThread->start();
}

void RecipeEngine::cancelAsync() {
    if (m_workerThread) {
        if (m_workerThread->isRunning()) {
            m_workerThread->requestInterruption();
            m_workerThread->quit();
            m_workerThread->wait(3000);
        }
        m_workerThread = nullptr;
    }
}

std::string RecipeEngine::run(const std::string &input, std::vector<RecipeStep> &steps, int debug_until_step) {
    QElapsedTimer timer;
    timer.start();

    std::string current_data = input;
    int steps_run = 0;

    for (int i = 0; i < (int)steps.size(); i++) {
        if (debug_until_step != -1 && i > debug_until_step)
            break;

        RecipeStep &step = steps[i];
        if (!step.enabled) {
            step.intermediate_output = current_data;
            step.has_error = false;
            step.error_message.clear();
            step.execution_time_ms = 0.0;
            continue;
        }

        QElapsedTimer step_timer;
        step_timer.start();

        bool success = true;
        std::string error_msg;
        std::string step_output = executeSingleStep(current_data, step, success, error_msg);

        double elapsed_step = step_timer.nsecsElapsed() / 1000000.0;
        step.execution_time_ms = elapsed_step;
        step.has_error = !success;
        step.error_message = error_msg;

        if (success) {
            current_data = step_output;
            step.intermediate_output = current_data;
            steps_run++;
            emit stepExecuted(i, true, elapsed_step);
        } else {
            step.intermediate_output = current_data;
            emit stepExecuted(i, false, elapsed_step);
            break;
        }
    }

    double total_ms = timer.nsecsElapsed() / 1000000.0;
    m_metrics.total_time_ms = total_ms;
    m_metrics.timestamp = QDateTime::currentDateTime();

    if (total_ms > 0) {
        double bytes = input.size() + current_data.size();
        m_metrics.throughput_mbs = (bytes / 1024.0 / 1024.0) / (total_ms / 1000.0);
    } else {
        m_metrics.throughput_mbs = 0;
    }
    m_metrics.memory_used_bytes = input.size() + current_data.size() + (steps_run * 1024);

    emit executionFinished(current_data, m_metrics);
    return current_data;
}

void RecipeEngine::syncResultsToModel(RecipeModel *model) const {
    for (size_t i = 0; i < m_asyncSteps.size(); ++i) {
        const auto &s = m_asyncSteps[i];
        model->setStepResult(i, s.intermediate_output, s.has_error, s.error_message, s.execution_time_ms);
    }
}

std::string RecipeEngine::executeSingleStep(const std::string &input, const RecipeStep &step, bool &success, std::string &error_msg) {
    success = true;
    error_msg.clear();
    std::string out;

    const std::string &op = step.operation_name;
    const StepParams &p = step.params;

    try {
        if (op == "Caesar") {
            custom_rot(input, p.param1, out);
        } else if (op == "ROT13") {
            rot13(input, out);
        } else if (op == "ROT47") {
            rot47(input, out);
        } else if (op == "Atbash") {
            atbash(input, out);
        } else if (op == "Vigenere") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            vigenere(input, p.key, out, p.encrypt);
        } else if (op == "Playfair") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            playfair(input, out, p.key, p.encrypt);
        } else if (op == "Affine") {
            affine(input, out, p.param1, p.param2, p.encrypt);
        } else if (op == "Railfence") {
            railfence(input, out, p.param1, p.param2);
        } else if (op == "Columnar") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            if (p.encrypt) {
                columnar_encrypt(input, out, p.key);
            } else {
                int cols = (int)p.key.size();
                int rows = ((int)input.size() + cols - 1) / cols;
                columnar_decrypt(input, out, p.key, rows * cols);
            }
        } else if (op == "XOR (hex key)") {
            std::string k;
            for (size_t i = 0; i + 1 < p.key.size(); i += 2) {
                std::string pair = {p.key[i], p.key[i+1]};
                long long v; base_deconvert(pair, v, 16);
                k += (char)(unsigned char)v;
            }
            if (k.empty()) k = p.key;
            if (k.empty()) { success = false; error_msg = "XOR key cannot be empty"; return input; }
            out = input;
            for (size_t i = 0; i < input.size(); i++) {
                out[i] = input[i] ^ k[i % k.size()];
            }
        } else if (op == "RC4") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            rc4(input, out, p.key);
        } else if (op == "Blowfish") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            blowfish_ecb(input, out, p.key, p.encrypt);
        } else if (op == "DES") {
            if (p.key.size() != 16) { success = false; error_msg = "DES hex key must be 16 characters (8 bytes)"; return input; }
            des_ecb(input, out, p.key, p.encrypt);
        } else if (op == "Morse") {
            if (p.encrypt) morse_encode(input, out);
            else morse_decode(input, out);
        } else if (op == "Baconian") {
            bacon(input, out, p.encrypt);
        } else if (op == "Binary") {
            binary(input, out, p.encrypt);
        } else if (op == "Octal") {
            octal(input, out, p.encrypt);
        } else if (op == "Base64") {
            if (p.encrypt) {
                const std::string b64alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                proper_base_convert(input, out, 6, b64alpha);
            } else {
                out = base64url_decode(input);
            }
        } else if (op == "Hex") {
            if (p.encrypt) {
                const std::string hexalpha = "0123456789ABCDEF";
                proper_base_convert(input, out, 4, hexalpha);
            } else {
                out.clear();
                for (size_t i = 0; i + 1 < input.size(); i += 2) {
                    if (isspace(input[i])) { i--; continue; }
                    std::string pair = input.substr(i, 2);
                    char byte = (char)strtol(pair.c_str(), nullptr, 16);
                    out.push_back(byte);
                }
            }
        } else if (op == "URL Encode") {
            urlcode(input, out, p.encrypt);
        } else if (op == "Keyword") {
            if (p.key.empty()) { success = false; error_msg = "Keyword cannot be empty"; return input; }
            keyword_cipher(input, out, p.key, p.encrypt);
        } else if (op == "Substitution") {
            if (p.key.size() != 26) { success = false; error_msg = "Substitution alphabet must be 26 characters"; return input; }
            if (p.encrypt) substitution_encrypt(input, out, p.key);
            else substitution_decrypt(input, out, p.key);
        } else if (op == "A1Z26") {
            a1z26(input, out);
        } else if (op == "Keyboard Shift") {
            keyboard_shift(input, out, p.param1, p.encrypt);
        } else if (op == "Beaufort") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            beaufort(input, p.key, out);
        } else if (op == "Autokey") {
            if (p.key.empty()) { success = false; error_msg = "Key cannot be empty"; return input; }
            autokey(input, p.key, out, p.encrypt);
        } else if (op == "Scytale") {
            if (p.param1 <= 0) { success = false; error_msg = "Columns count must be greater than 0"; return input; }
            if (p.encrypt) scytale_encrypt(input, out, p.param1);
            else scytale_decrypt(input, out, p.param1);
        } else if (op == "Polybius Square") {
            if (p.encrypt) polybius_encrypt("ABCDEFGHIKLMNOPQRSTUVWXYZ", input, out);
            else polybius_decrypt("ABCDEFGHIKLMNOPQRSTUVWXYZ", input, out);
        } else if (op == "Bifid") {
            std::string rows[5] = {"ABCDE","FGHIK","LMNOP","QRSTU","VWXYZ"};
            char grid[6][6]; int row_of[256]={}, col_of[256]={};
            build_bifid_grid(rows, grid, row_of, col_of);
            if (p.encrypt) bifid_encrypt(input, out, grid, row_of, col_of);
            else bifid_decrypt(input, out, grid, row_of, col_of);
        } else if (op == "Trifid") {
            trifid(input, out, p.key, p.param1, p.encrypt);
        } else if (op == "Four-Square") {
            four_square(input, out, p.key, p.key, p.encrypt);
        }
        else if (op == "AES-ECB" || op == "AES-CBC" || op == "AES-CTR") {
            int mode = (op == "AES-ECB") ? 0 : (op == "AES-CBC") ? 1 : 2;
            std::string real_key = p.key;
            if (real_key.size() != 16 && real_key.size() != 32) {
                if (real_key.size() < 16) real_key.resize(16, 0x00);
                else if (real_key.size() < 32) real_key.resize(32, 0x00);
                else real_key.resize(32);
            }
            std::string real_iv = p.iv;
            if (real_iv.size() != 16) real_iv.resize(16, 0x00);
            if (p.encrypt) success = aes_encrypt(input, real_key, real_iv, mode, out);
            else success = aes_decrypt(input, real_key, real_iv, mode, out);
            if (!success) error_msg = "AES encryption/decryption failed (verify key/padding)";
        } else if (op == "ChaCha20") {
            std::string real_key = p.key;
            real_key.resize(32, 0x00);
            std::string real_nonce = p.iv;
            real_nonce.resize(12, 0x00);
            chacha20_crypt(input, real_key, real_nonce, p.param1, out);
        } else if (op == "Poly1305") {
            std::string real_key = p.key;
            real_key.resize(32, 0x00);
            poly1305_mac(input, real_key, out);
        } else if (op == "HMAC-SHA256") {
            hmac_sha256(input, p.key, out);
            out = from_hex(out);
        } else if (op == "HMAC-SHA512") {
            hmac_sha512(input, p.key, out);
            out = from_hex(out);
        }
        else if (op == "MD5") {
            md5_hash(input, out);
            out = from_hex(out);
        } else if (op == "SHA-1") {
            sha1_hash(input, out);
            out = from_hex(out);
        } else if (op == "SHA-256") {
            sha256_hash(input, out);
            out = from_hex(out);
        } else if (op == "SHA-512") {
            sha512_hash(input, out);
            out = from_hex(out);
        } else if (op == "BLAKE2b") {
            blake2b_hash(input, out, p.key);
            out = from_hex(out);
        } else if (op == "BLAKE2s") {
            blake2s_hash(input, out, p.key);
            out = from_hex(out);
        } else if (op == "PBKDF2-SHA256") {
            std::string salt = p.iv;
            uint32_t iter = std::max(1, p.param1);
            uint32_t klen = std::max(8, p.param2);
            pbkdf2_sha256(input, salt, iter, klen, out);
            out = from_hex(out);
        } else if (op == "Argon2id") {
            std::string salt = p.iv;
            uint32_t iter = std::max(1, p.param1);
            uint32_t mem = std::max(8, p.param2);
            success = argon2id_hash(input, salt, iter, mem, 1, 32, out);
            out = from_hex(out);
            if (!success) error_msg = "Argon2id KDF failed";
        }
        else if (op == "JWT Sign") {
            std::string header = p.iv;
            if (header.empty()) header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            out = jwt_sign(header, input, p.key);
        } else if (op == "JWT Verify") {
            JwtToken jt = jwt_parse(input, p.key);
            if (jt.header.empty()) {
                success = false;
                error_msg = "Invalid JWT structure";
            } else {
                out = "Header: " + jt.header + "\nPayload: " + jt.payload + "\nSignature Valid: " + (jt.signature_valid ? "YES" : "NO");
            }
        } else if (op == "QR Code") {
            std::vector<std::vector<bool>> qr = generate_qr_matrix(input);
            std::stringstream ss;
            for (auto &row : qr) {
                for (bool cell : row) ss << (cell ? "██" : "  ");
                ss << "\n";
            }
            out = ss.str();
        } else if (op == "LSB Embed") {
            if (p.key.empty()) { success = false; error_msg = "Data to embed (Key) cannot be empty"; return input; }
            success = lsb_embed(input, p.key, out);
            if (!success) error_msg = "LSB embedding failed (carrier input too small)";
        } else if (op == "LSB Extract") {
            success = lsb_extract(input, out);
            if (!success) error_msg = "LSB extraction failed (no embedded data detected)";
        } else if (op == "Leetspeak") {
            out = input;
            for (char &c : out) {
                char ch = toupper((unsigned char)c);
                if (ch == 'A') c = '4';
                else if (ch == 'E') c = '3';
                else if (ch == 'G') c = '6';
                else if (ch == 'I') c = '1';
                else if (ch == 'O') c = '0';
                else if (ch == 'S') c = '5';
                else if (ch == 'T') c = '7';
                else if (ch == 'Z') c = '2';
            }
        } else if (m_pluginLoader) {
            std::string pluginOut = m_pluginLoader->tryExecute(op, input,
                p.key, p.iv, p.param1, p.param2, p.encrypt, success, error_msg);
            if (success) out = pluginOut;
            else if (error_msg.empty()) {
                success = false;
                error_msg = "Unknown operation: " + op;
                return input;
            }
        } else {
            success = false;
            error_msg = "Unknown operation: " + op;
            return input;
        }
    } catch (const std::exception &e) {
        success = false;
        error_msg = std::string("Crash inside operation: ") + e.what();
        return input;
    }

    return out;
}

bool RecipeEngine::parseMacroScript(const std::string &script, RecipeModel *model, std::string &error_msg) {
    model->clear();
    QStringList sections = QString::fromStdString(script).split('|');

    for (int i = 0; i < sections.size(); ++i) {
        QString sec = sections[i].trimmed();
        if (sec.isEmpty()) continue;

        QRegularExpression re("([a-zA-Z0-9_\\-\\s\\(\\)]+)(?:\\((.*)\\))?");
        QRegularExpressionMatch match = re.match(sec);
        if (!match.hasMatch()) {
            error_msg = "Malformed macro command: " + sec.toStdString();
            return false;
        }

        QString raw_name = match.captured(1).trimmed();
        if (raw_name.endsWith("()")) raw_name.chop(2);
        raw_name = raw_name.trimmed();
        std::string cmd = raw_name.toStdString();

        std::string mapped_name = cmd;
        if (cmd == "rot13") mapped_name = "ROT13";
        else if (cmd == "rot47") mapped_name = "ROT47";
        else if (cmd == "caesar") mapped_name = "Caesar";
        else if (cmd == "base64") mapped_name = "Base64";
        else if (cmd == "hex") mapped_name = "Hex";
        else if (cmd == "aes") mapped_name = "AES-CBC";
        else if (cmd == "chacha") mapped_name = "ChaCha20";
        else if (cmd == "vigenere") mapped_name = "Vigenere";
        else if (cmd == "sha256") mapped_name = "SHA-256";
        else if (cmd == "md5") mapped_name = "MD5";

        QString args = match.captured(2).trimmed();
        StepParams p;

        if (!args.isEmpty()) {
            QStringList kv_pairs = args.split(',');
            for (QString kv : kv_pairs) {
                QStringList parts = kv.split('=');
                if (parts.size() == 2) {
                    QString k = parts[0].trimmed().toLower();
                    QString v = parts[1].trimmed();
                    if ((v.startsWith("'") && v.endsWith("'")) || (v.startsWith("\"") && v.endsWith("\""))) {
                        v.chop(1);
                        v.remove(0, 1);
                    }
                    if (k == "key") p.key = v.toStdString();
                    else if (k == "iv") p.iv = v.toStdString();
                    else if (k == "p1" || k == "param1" || k == "shift" || k == "cols") p.param1 = v.toInt();
                    else if (k == "p2" || k == "param2") p.param2 = v.toInt();
                    else if (k == "dec" || k == "decrypt") p.encrypt = (v.toLower() != "true" && v != "1");
                }
            }
        }

        model->addStep(mapped_name, p);
    }
    return true;
}

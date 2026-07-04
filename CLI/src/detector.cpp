#include "../includes/detector.h"
#include "../includes/branch_explorer.h"
#include "../includes/basic_ciphers.h"
#include "../includes/historical_ciphers.h"
#include "../includes/essential_ciphers.h"
#include "../includes/bruteforce_ciphers.h"
#include "../includes/standard_ciphers.h"
#include "../includes/bigint.hpp"
#include "../includes/quadgram.h"
#include <cctype>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <cstring>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <limits>
#include <numeric>

static const double ENG_FREQ[26] = {
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094,
    6.966, 0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929,
    0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
    1.974, 0.074
};

static const char *DIGRAPHS[30] = {
    "TH", "HE", "IN", "ER", "AN", "RE", "ED", "ON", "ES", "ST",
    "EN", "AT", "TO", "NT", "HA", "ND", "OU", "EA", "NG", "AL",
    "IT", "AS", "IS", "ET", "OR", "TI", "AR", "TE", "SE", "HI"
};

static const double DIGRAPH_FREQ[30] = {
    3.56, 2.74, 2.37, 2.35, 2.17, 1.85, 1.62, 1.56, 1.55, 1.52,
    1.45, 1.41, 1.35, 1.26, 1.22, 1.18, 1.15, 1.11, 1.05, 1.04,
    1.02, 0.99, 0.97, 0.95, 0.94, 0.93, 0.91, 0.90, 0.88, 0.87
};

static const int MAX_DEPTH = 3;
static const int MAX_CANDIDATES = 500;
static const double HIGH_CONF_THRESHOLD = 0.85;
static const double RECURSE_CHI_SQ = 30.0;
static const double kAcceptScoreHigh = 80.0;
static const double kAcceptScoreMid = 100.0;
static const double kAcceptScoreLow = 60.0;
static const double kMonoalphabeticIocLow = 0.055;
static const double kPolyalphabeticIocMax = 0.075;
static const double kXorEntropyMax = 6.5;
static const double kEnglishIocMid = 0.066;
static thread_local bool g_aggressive = false;

struct DetectorPass {
    std::string name;
    std::function<std::vector<CipherCandidate>(const std::string&)> run;
    bool always_run;
};

static double chi_sq_to_confidence(double chi_sq) {
    if (chi_sq < 0.0) chi_sq = 0.0;
    if (chi_sq <= 15.0) return 0.95 - 0.02 * chi_sq / 15.0;
    if (chi_sq <= 100.0) return 0.65 + 0.28 * (1.0 - (chi_sq - 15.0) / 85.0);
    if (chi_sq <= 400.0) return 0.15 + 0.50 * (1.0 - (chi_sq - 100.0) / 300.0);
    if (chi_sq <= 1000.0) return 0.04 + 0.11 * (1.0 - (chi_sq - 400.0) / 600.0);
    return 0.03;
}

static double normalize_confidence(double raw_chi_sq, const std::string &family) {
    if (raw_chi_sq < 0.0) raw_chi_sq = 0.0;
    if (family == "encoding") {
        if (raw_chi_sq <= 5.0) return 0.95;
        if (raw_chi_sq <= 20.0) return 0.85 - 0.1 * (raw_chi_sq - 5.0) / 15.0;
        if (raw_chi_sq <= 100.0) return 0.60 - 0.25 * (raw_chi_sq - 20.0) / 80.0;
        return 0.30;
    }
    if (family == "substitution") {
        if (raw_chi_sq <= 10.0) return 0.75 + 0.15 * (1.0 - raw_chi_sq / 10.0);
        if (raw_chi_sq <= 50.0) return 0.40 + 0.35 * (1.0 - (raw_chi_sq - 10.0) / 40.0);
        if (raw_chi_sq <= 200.0) return 0.10 + 0.30 * (1.0 - (raw_chi_sq - 50.0) / 150.0);
        return 0.05;
    }
    if (family == "transposition") {
        if (raw_chi_sq <= 15.0) return 0.70 + 0.15 * (1.0 - raw_chi_sq / 15.0);
        if (raw_chi_sq <= 60.0) return 0.35 + 0.35 * (1.0 - (raw_chi_sq - 15.0) / 45.0);
        if (raw_chi_sq <= 200.0) return 0.10 + 0.25 * (1.0 - (raw_chi_sq - 60.0) / 140.0);
        return 0.05;
    }
    if (family == "xor") {
        if (raw_chi_sq <= 10.0) return 0.85 + 0.10 * (1.0 - raw_chi_sq / 10.0);
        if (raw_chi_sq <= 40.0) return 0.45 + 0.40 * (1.0 - (raw_chi_sq - 10.0) / 30.0);
        if (raw_chi_sq <= 150.0) return 0.15 + 0.30 * (1.0 - (raw_chi_sq - 40.0) / 110.0);
        return 0.05;
    }
    return chi_sq_to_confidence(raw_chi_sq);
}

static std::string to_upper(const std::string &s) {
    std::string r;
    r.reserve(s.size());
    for (unsigned char ch : s) r += (char)std::toupper(ch);
    return r;
}

static std::string strip_spaces(const std::string &s) {
    std::string r;
    for (unsigned char ch : s)
        if (!std::isspace(ch)) r += ch;
    return r;
}

static double score_digraph_english(const std::string &text) {
    std::string upper = to_upper(text);
    std::string clean;
    for (unsigned char ch : upper)
        if (ch >= 'A' && ch <= 'Z') clean += ch;
    if (clean.size() < 4) return 999999.0;
    double expected[26][26] = {{0}};
    for (int i = 0; i < 30; i++) {
        int a = DIGRAPHS[i][0] - 'A';
        int b = DIGRAPHS[i][1] - 'A';
        expected[a][b] = DIGRAPH_FREQ[i];
    }
    double total_expected = 0;
    for (int i = 0; i < 26; i++)
        for (int j = 0; j < 26; j++)
            total_expected += expected[i][j];
    if (total_expected < 0.01) return 999999.0;
    double dig_chi_sq = 0.0;
    int dig_count = 0;
    for (size_t i = 0; i + 1 < clean.size(); i++) {
        int a = clean[i] - 'A';
        int b = clean[i+1] - 'A';
        if (a < 0 || a > 25 || b < 0 || b > 25) continue;
        double observed = 100.0 / (clean.size() - 1);
        double exp = expected[a][b];
        if (exp < 0.001) exp = 0.1;
        double diff = observed - exp;
        dig_chi_sq += (diff * diff) / exp;
        dig_count++;
    }
    if (dig_count == 0) return 999999.0;
    return dig_chi_sq / dig_count * 10.0;
}

double score_english(const std::string &text) {
    int counts[26] = {0};
    int total = 0;
    for (unsigned char ch : text) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }
    if (total == 0) return 999999.0;
    double chi_sq = 0.0;
    for (int i = 0; i < 26; i++) {
        double observed = (100.0 * counts[i]) / total;
        double diff = observed - ENG_FREQ[i];
        chi_sq += (diff * diff) / ENG_FREQ[i];
    }
    return chi_sq;
}

static const std::unordered_set<std::string> COMMON_WORDS_SET = {
    "the","be","to","of","and","a","in","that","have","i","it","for","not","on","with","he",
    "as","you","do","at","this","but","his","by","from","they","we","say","her","she","or",
    "an","will","my","one","all","would","there","their","what","so","up","out","if","about",
    "who","get","which","go","me","when","make","can","like","time","no","just","him","know",
    "take","people","into","year","your","good","some","could","them","see","other","than",
    "then","now","look","only","come","its","over","think","also","back","after","use","two",
    "how","our","work","first","well","way","even","new","want","because","any","these","give",
    "day","most","us","great","between","need","large","often","hand","high","place","small",
    "under","long","right","still","own","should","home","every","last","might","man","read",
    "old","where","much","mean","keep","same","start","child","city","state","eye","never",
    "another","world","head","above","group","country","part","life","add","house","family",
    "school","before","move","stand","side","found","water","change","off","turn","room","young",
    "point","member","number","course","line","order","woman","learn","plant","face","week","end",
    "among","given","question","play","power","town","short","several","black","white","red",
    "blue","green","yellow","big","long","little","next","early","late","open","close","high",
    "low","hard","easy","free","full","sure","real","true","left","right","good","bad","best",
    "better","wrong","public","private","common","rare","simple","complex","clear","dark","light",
    "heavy","fast","slow","hot","cold","warm","cool","soft","strong","weak","deep","rich","poor",
    "rough","smooth","sharp","dull","sweet","loud","quiet","near","far","thick","thin","wide",
    "narrow","local","global","modern","current","future","past","present","final","initial",
    "entire","total","major","minor","single","double","multiple","separate","certain","possible",
    "necessary","primary","secondary","original","direct","positive","negative","active","passive",
    "simple","difficult","cheap","expensive","quick","safe","dangerous","wise","legal","formal",
    "proper","fair","capable","complete","correct","accurate","normal","perfect","pleasant",
    "popular","adequate","sufficient","valid","happy","sad","angry","calm","brave","proud",
    "eager","lazy","generous","kind","cruel","polite","rude","honest","clever","stupid","gentle",
    "tough","helpful","useless","careful","peaceful","violent","lovely","horrible","beautiful",
    "ugly","graceful","fancy","plain","fierce","strict","famous","strange","natural","genuine",
    "fake","fresh","stale","clean","dirty","neat","messy","dry","wet","empty","full","silent",
    "noisy","still","constant","steady","equal","same","different","similar","various","stable",
    "solid","rigid","flexible","fragile","modest","grand","humble","moderate","extreme","mild",
    "hello","world","intense","vague","clear","bright","dim","brief","short","long","dense","sparse","fat","slim",
    "heavy","light","tall","great","tiny","huge","vast","massive","steep","sudden","rapid","smart",
    "cloudy","sunny","rainy","windy","mild","harsh","warm","cool","hot","cold","frozen","melted",
    "hard","soft","coarse","fine","bumpy","flat","straight","bent","curved","forward","backward",
    "upward","downward","north","south","east","west","central","middle","inner","outer","upper",
    "lower","top","bottom","front","back","left","right","center","core","inside","outside",
    "above","below","over","under","across","through","around","between","among","beyond","within",
    "without","against","toward","along","during","before","after","since","until","while","when",
    "where","why","how","what","which","who","whether","however","therefore","otherwise",
    "furthermore","meanwhile","notably","especially","namely","mainly","mostly","primarily",
    "nearly","almost","virtually","merely","barely","hardly","simply","just","only","alone",
    "pure","utter","absolute","complete","total","entire","full","whole","partial","slight",
    "significant","substantial","ample","abundant","excessive","extreme","severe","grave","serious",
    "strict","firm","tough","heavy","strong","robust","durable","vigorous","energetic","dynamic",
    "active","lively","quick","fast","rapid","swift","urgent","critical","essential","vital",
    "necessary","mandatory","optional","random","casual","cheerful","happy","glad","delighted",
    "peaceful","calm","still","quiet","soft","gentle","pleasant","nice","lovely","enjoyable",
    "valuable","precious","dear","sacred","devoted","dedicated","committed","loyal","faithful",
    "true","constant","firm","resolute","determined","persistent","stubborn","random","erratic",
    "unstable","uncertain","doubtful","skeptical","cautious","careful","prudent","sensible",
    "practical","realistic","rational","logical","reasonable","valid","legitimate","appropriate",
    "proper","correct","right","accurate","precise","exact","specific","particular","definite",
    "clear","distinct","plain","obvious","evident","apparent","visible","tangible","real","actual",
    "genuine","authentic","legal","lawful","sound","true","correct","accurate","faithful","loyal",
    "devoted","steady","tireless","weary","exhausted","depleted","reduced","decreased","increased",
    "followed","pursued","searched","cleaned","washed","smoothed","adjusted","balanced","changed",
    "altered","modified","converted","transformed","developed","matured","hardened","divided",
    "separated","torn","broken","destroyed","ruined","removed","erased","deleted","reversed",
    "changed","advanced","basic","complex","deep","shallow","profound","intense","powerful","potent",
    "strong","forceful","energetic","vivid","detailed","thorough","comprehensive","exhaustive",
    "complete","total","absolute","sheer","pure","perfect","ideal","typical","unique","unusual",
    "remarkable","notable","memorable","permanent","lasting","enduring","persistent","constant",
    "continuous","eternal","annual","monthly","weekly","daily","frequent","regular","habitual",
    "usual","normal","ordinary","common","standard","typical","traditional","established","fixed",
    "final","complete","finished","done","stopped","dead","inactive","idle","stable","uniform",
    "regular","steady","even","straight","direct","immediate","instant","quick","fast","rapid",
    "smooth","appropriate","proper","right","correct","accurate","precise","fine","subtle","delicate",
    "intricate","complex","elaborate","sharp","keen","pungent","spicy","hot","wet","damp","moist",
    "dry","foul","nasty","disgusting","repulsive","hateful","horrible","hideous","creepy","weird",
    "strange","odd","bizarre","wild","crazy","mad","angry","furious","irate","annoyed","upset",
    "confused","puzzled","baffled","surprised","amazed","astonished","impressed","moved","affected",
    "persuaded","convinced","sure","certain","positive","confident","firm","unyielding","stubborn",
    "reluctant","hesitant","opposed","resistant","rebellious","conservative","modern","established",
    "qualified","competent","capable","able","skillful","expert","clever","smart","bright","intelligent",
    "brilliant","wise","keen","sharp","thoughtful","romantic","sentimental","emotional","passionate",
    "fierce","intense","powerful","strong","lively","vivid","bright","shining","pale","dull",
    "dark","gloomy","dim","shadowy","foggy","cloudy","gray","dreary","bleak","barren","empty",
    "vacant","clean","clear","pure","fresh","new","original","creative","ambitious","motivated",
    "dedicated","committed","devoted","loyal","faithful","steady","secure","safe","protected",
    "strong","firm","durable","stable","steady","balanced","fair","just","neutral","open","broad",
    "wide","universal","general","common","dominant","principal","main","major","chief","primary",
    "key","central","core","fundamental","basic","essential","vital","critical","important",
    "significant","serious","earnest","sincere","genuine","real","true","authentic","valid","good",
    "sound","reliable","dependable","trustworthy","steady","absolute","complete","full","entire",
    "whole","pure","perfect","excellent","outstanding","exceptional","remarkable","extraordinary",
    "unique","superb","magnificent","splendid","wonderful","fantastic","tremendous","immense",
    "vast","enormous","gigantic","huge","massive","spacious","abundant","extensive","broad","wide",
    "global","international","diverse","numerous","many","countless","several","multiple","various",
    "different","distinct","separate","individual","particular","specific","special","secret",
    "hidden","mysterious","false","fake","artificial","synthetic","mock","minimum","minimal",
    "trivial","insignificant","minor","petty","small","little","slight","limited","restricted",
    "controlled","managed","conducted","performed","achieved","obtained","won","deserved","justified",
    "forgiven","excused","ignored","missed","broken","shattered","split","divided","cut","torn",
    "burst","exploded","fired","shot","threw","raised","lifted","improved","enhanced","strengthened",
    "combined","joined","linked","connected","united","included","contained","covered","extended",
    "reached","touched","received","accepted","adopted","carried","supported","maintained","kept",
    "preserved","saved","stored","collected","gathered","assembled","filled","loaded","covered",
    "topped","pointed","shortened","trimmed","cut","stripped","bare","exposed","revealed","showed",
    "displayed","presented","offered","proposed","suggested","advised","encouraged","prompted",
    "is","was","are","were","been","has","had","have","not","but","what","can","each",
    "most","very","just","also","more","than","other","into","about","could","would","should",
    "test","message","text","example","using","called","used","being","said","who","may",
    "many","some","them","these","those","here","there","where","when","why","how",
    "back","does","which","their","your","its","two","way","day","come","came",
    "made","make","take","like","time","year","people","thing","name","line",
    "need","know","think","help","work","look","find","want","give","tell","say",
    "first","then","next","well","much","such","here","down","show","form",
    "word","part","place","case","week","hand","side","turn","mean","land",
    "life","hand","high","state","group","play","live","read","keep","start",
    "face","home","city","talk","away","long","still","own","ever","never","always",
    "number","water","room","area","order","point","large","small","right","left",
    "open","close","hard","soft","best","real","true","free","full","love","hope",
    "few","big","old","new","young","great","short","clear","light","dark","deep",
    "far","near","high","low","hot","cold","warm","cool","happy","sad","kind",
    "thing","things","while","before","after","since","until","about","between",
    "across","through","over","under","again","often","always","never","maybe",
    "along","around","back","even","still","already","yet","almost","enough",
    "another","family","school","country","world","house","table","doctor","hi",
    "quick","brown","fox","jumps","lazy","dog","over","hello","world","from",
    "the","this","that","with","have","will","your","which","their","them",
    "call","some","these","would","about","other","could","after","then",
    "more","also","very","just","than","been","were","been","being","said",
    "does","each","most","thing","many","some","them","those","here","there",
    "where","when","why","how","back","does","which","their","your","its",
    "two","way","day","come","came","made","make","take","like","time",
    "year","people","thing","name","line","need","know","think","help",
    "work","look","find","want","give","tell","say","first","then","next",
    "well","much","such","here","down","show","form","word","part","place",
    "case","week","hand","side","turn","mean","land","life","hand","high",
    "state","group","play","live","read","keep","start","face","home","city",
    "talk","away","long","still","own","ever","never","always","number",
    "water","room","area","order","point","large","small","right","left",
    "open","close","hard","soft","best","real","true","free","full","love",
    "hope","few","big","old","new","young","great","short","clear","light",
    "dark","deep","far","near","high","low","hot","cold","warm","cool",
    "happy","sad","kind","thing","things","while","before","after","since",
    "until","about","between","across","through","over","under","again",
    "often","always","never","maybe","along","around","back","even","still",
    "already","yet","almost","enough","another","family","school","country",
    "world","house","table","doctor","say","help","low","keep","ever",
    "never","always","often","maybe","show","try","ask","need","feel",
    "become","leave","put","mean","let","begin","move","live","run",
    "change","play","spell","add","set","stand","thus","yes","no",
    "shall","must","may","might","can","could","would","should",
    "follow","lead","see","seem","call","serve","wait","wish","bring",
    "write","give","begin","show","hear","watch","let","run","move",
    "live","stand","hear","believe","hold","study","happen","grow",
    "draw","carry","set","fall","cut","raise","sit","kill","remain",
    "produce","receive","agree","support","die","appear","rest","create",
    "contain","reduce","establish","explain","offer","stop","continue",
    "prove","fix","spend","forget","manage","consider","allow","fill",
    "argue","pass","sell","require","report","decide","pull","push",
    "recognize","refer","serve","suppose","apply","imagine","reach",
    "choose","identify","determine","prepare","suggest","maintain",
    "insist","repeat","divide","express","represent","claim","indicate",
    "expect","involve","provide","pretend","avoid","prevent","admit",
    "reject","accept","assume","conclude","proceed","define","respond",
    "achieve","perform","adopt","acquire","administer","analyze",
    "associate","aware","benefit","cause","circumstance","claim",
    "community","concern","condition","consequence","consumer",
    "contribute","convention","cooperation","corner","culture",
    "decade","defense","direction","economy","effect","effort",
    "emphasis","employee","environment","establishment","evidence",
    "expansion","expert","facility","foundation","freedom",
    "identify","illustrate","impact","implementation","implication",
    "improvement","independence","indication","infrastructure",
    "initiative","institution","instrument","insurance",
    "interpretation","investigation","involvement","issue",
    "judgment","justification","knowledge","legislation",
    "liability","maintenance","management","manipulation",
    "measurement","mechanism","negotiation","obligation",
    "operation","opposition","organization","participation",
    "partnership","perception","performance","phenomenon",
    "philosophy","policy","possession","preference","procedure",
    "profession","proportion","publication","pursuit",
    "recommendation","reference","regulation","relationship",
    "requirement","resolution","resource","responsibility",
    "restriction","revenue","satisfaction","security",
    "situation","strategy","structure","substance",
    "sufficiency","supervision","supplement","symposium",
    "terminology","tradition","transformation","transportation",
    "utilization","variation","version","vision",
};

static int count_compact_common_words(const std::string &text) {
    static const std::vector<std::string> compact_words = {
        "this", "that", "there", "their", "secret", "message", "quick", "brown",
        "jumps", "over", "lazy", "hello", "world", "attack", "plain", "text",
        "cipher", "the", "fox", "dog", "test"
    };
    std::string lower;
    lower.reserve(text.size());
    for (unsigned char ch : text) {
        if (std::isalpha(ch)) lower += (char)std::tolower(ch);
    }
    int hits = 0;
    for (const auto &word : compact_words) {
        if (lower.find(word) != std::string::npos) hits++;
    }
    return hits;
}

static std::string split_pascal_case(const std::string &s) {
    std::string r;
    for (size_t i = 0; i < s.size(); i++) {
        if (i > 0 && s[i] >= 'A' && s[i] <= 'Z' && s[i-1] >= 'a' && s[i-1] <= 'z')
            r += ' ';
        r += s[i];
    }
    return r;
}

double score_english_combined(const std::string &text) {
    double chi_sq = score_english(text);

    std::string lower = split_pascal_case(text);
    for (char &ch : lower) {
        if (ch >= 'A' && ch <= 'Z') ch += 32;
    }

    int word_hits = 0;
    size_t pos = 0;
    while (pos < lower.size()) {
        while (pos < lower.size() && !std::isalpha((unsigned char)lower[pos])) pos++;
        if (pos >= lower.size()) break;
        size_t end = pos;
        while (end < lower.size() && std::isalpha((unsigned char)lower[end])) end++;
        std::string word = lower.substr(pos, end - pos);
        if (word.size() >= 2 && COMMON_WORDS_SET.count(word) > 0) {
            word_hits++;
        }
        pos = end;
    }
    word_hits += count_compact_common_words(text);

    double word_bonus = std::min((double)word_hits * 0.08, 0.6);
    size_t tlen = text.size();
    if (tlen < 20)
        word_bonus = std::min(word_bonus * 4.0, 0.9);
    else if (tlen < 40)
        word_bonus = std::min(word_bonus * 3.0, 0.85);
    else if (tlen < 60)
        word_bonus = std::min(word_bonus * 2.0, 0.8);

    return chi_sq * (1.0 - word_bonus);
}

double compute_entropy(const std::string &input) {
    if (input.empty()) return 0.0;
    int counts[256] = {0};
    for (unsigned char ch : input) counts[ch]++;
    double entropy = 0.0;
    double len = (double)input.size();
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = counts[i] / len;
        entropy -= p * log2(p);
    }
    return entropy;
}

double compute_ioc(const std::string &input) {
    int counts[26] = {0};
    int total = 0;
    for (unsigned char ch : input) {
        if (ch >= 'A' && ch <= 'Z') { counts[ch - 'A']++; total++; }
        else if (ch >= 'a' && ch <= 'z') { counts[ch - 'a']++; total++; }
    }
    if (total <= 1) return 0.0;
    double sum = 0.0;
    for (int i = 0; i < 26; i++) sum += counts[i] * (counts[i] - 1.0);
    return sum / (total * (total - 1.0));
}

static std::string hex_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch)) clean += ch;
    }
    std::string out;
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        std::string pair = {clean[i], clean[i + 1]};
        long long val;
        base_deconvert(pair, val, 16);
        out += (char)(unsigned char)val;
    }
    return out;
}

static int b64_val(unsigned char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9') return ch - '0' + 52;
    if (ch == '+') return 62;
    if (ch == '/') return 63;
    return -1;
}

static std::string base64_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch) && ch != '=') clean += ch;
    }
    std::string out;
    size_t i = 0;
    for (; i + 3 < clean.size(); i += 4) {
        int v[4] = {b64_val(clean[i]), b64_val(clean[i+1]), b64_val(clean[i+2]), b64_val(clean[i+3])};
        out += (char)((v[0] << 2) | (v[1] >> 4));
        if (v[2] >= 0) out += (char)((v[1] << 4) | (v[2] >> 2));
        if (v[3] >= 0) out += (char)((v[2] << 6) | v[3]);
    }
    size_t rem = clean.size() - i;
    if (rem >= 2) {
        int v0 = b64_val(clean[i]);
        int v1 = b64_val(clean[i+1]);
        out += (char)((v0 << 2) | (v1 >> 4));
        if (rem >= 3) {
            int v2 = b64_val(clean[i+2]);
            out += (char)((v1 << 4) | (v2 >> 2));
        }
    }
    return out;
}

std::string sniff_encoding(const std::string &input) {
    if (input.empty()) return "text";
    bool high_byte = false;
    for (unsigned char ch : input) {
        if (ch > 0x7E) { high_byte = true; break; }
    }
    if (high_byte) return "binary";
    std::string clean;
    for (unsigned char ch : input) {
        if (!std::isspace(ch)) clean += ch;
    }
    if (clean.empty()) return "text";
    bool all_hex = true;
    for (unsigned char ch : clean) {
        if (!std::isxdigit(ch)) { all_hex = false; break; }
    }
    if (all_hex && (clean.size() % 2 == 0)) return "hex";
    bool all_b64 = true;
    for (unsigned char ch : clean) {
        if (!std::isalnum(ch) && ch != '+' && ch != '/' && ch != '=') {
            all_b64 = false; break;
        }
    }
    if (all_b64 && clean.size() >= 8 && (clean.size() % 4 == 0)) {
        std::string dec = base64_decode(input);
        bool has_non_printable = false;
        bool has_high_byte = false;
        int letter_count = 0;
        for (unsigned char ch : dec) {
            if (ch > 0x7E) has_high_byte = true;
            if (ch < 32 && ch != '\n' && ch != '\t' && ch != '\r') has_non_printable = true;
            if (std::isalpha(ch)) letter_count++;
        }
        if (has_high_byte) return "text";
        double letter_ratio = dec.empty() ? 1.0 : (double)letter_count / dec.size();
        if (has_non_printable || letter_ratio < 0.9)
            return "base64";
        bool has_b64_special = false;
        for (unsigned char ch : clean)
            if (ch >= '0' && ch <= '9') { has_b64_special = true; break; }
        if (!has_b64_special)
            for (unsigned char ch : clean)
                if (ch == '+' || ch == '/' || ch == '=') { has_b64_special = true; break; }
        if (has_b64_special && letter_ratio < 0.97)
            return "base64";
    }
    return "text";
}

static std::string base32_decode(const std::string &s) {
    const char *b32alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch) && ch != '=') clean += (char)std::toupper(ch);
    }
    std::string out;
    for (size_t i = 0; i + 7 < clean.size(); i += 8) {
        int v[8];
        for (int j = 0; j < 8; j++) {
            const char *p = strchr(b32alpha, clean[i + j]);
            v[j] = p ? (int)(p - b32alpha) : 0;
        }
        out += (char)((v[0] << 3) | (v[1] >> 2));
        out += (char)((v[1] << 6) | (v[2] << 1) | (v[3] >> 4));
        out += (char)((v[3] << 4) | (v[4] >> 1));
        out += (char)((v[4] << 7) | (v[5] << 2) | (v[6] >> 3));
        out += (char)((v[6] << 5) | v[7]);
    }
    return out;
}

static std::string base85_decode(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s) {
        if (!std::isspace(ch) && ch != '~') clean += ch;
    }
    if (!clean.empty() && clean[0] == '<') clean.erase(0, 1);
    if (!clean.empty() && clean.back() == '>') clean.pop_back();
    std::string out;
    size_t i = 0;
    while (i < clean.size()) {
        if (clean[i] == 'z') {
            out += std::string(4, '\0');
            i++;
            continue;
        }
        if (i + 4 >= clean.size()) break;
        unsigned int v = 0;
        for (int j = 0; j < 5; j++) {
            v = v * 85 + (unsigned char)(clean[i + j] - 33);
        }
        out += (char)((v >> 24) & 0xFF);
        out += (char)((v >> 16) & 0xFF);
        out += (char)((v >> 8) & 0xFF);
        out += (char)(v & 0xFF);
        i += 5;
    }
    int pad = 0;
    while (out.size() > 0 && pad < 4 && out.back() == '\0') {
        out.pop_back();
        pad++;
    }
    return out;
}

static std::string reverse_a1z26(const std::string &a, char sep) {
    std::stringstream ss(a);
    std::string token;
    std::string out;
    while (std::getline(ss, token, sep)) {
        if (token.empty()) continue;
        int val = std::atoi(token.c_str());
        if (val >= 1 && val <= 26)
            out += (char)('Z' - (val - 1));
    }
    return out;
}

enum class DetectedStructure {
    NONE,
    MORSE,
    BACON,
    A1Z26,
    HEX,
    BASE85,
    PLAYFAIR_LIKE,
    SINGLE_BYTE_XOR
};

static bool is_bacon_like(const std::string &s) {
    std::string clean = strip_spaces(s);
    if (clean.empty()) return false;
    char first = clean[0];
    if (!std::isalpha((unsigned char)first)) return false;
    char second = 0;
    for (unsigned char ch : clean) {
        if (ch != first && std::isalpha(ch)) { second = ch; break; }
    }
    if (second == 0) return false;
    for (unsigned char ch : clean)
        if (ch != first && ch != second) return false;
    return clean.size() % 5 == 0;
}

static bool is_morse_like(const std::string &s) {
    if (s.empty()) return false;
    bool has_dot = false, has_dash = false;
    for (unsigned char ch : s) {
        if (ch == '.') has_dot = true;
        else if (ch == '-') has_dash = true;
        else if (ch == ' ' || ch == '/' || ch == '\n') continue;
        else return false;
    }
    return has_dot || has_dash;
}

static bool is_a1z26_like(const std::string &s) {
    if (s.empty()) return false;
    bool has_digit = false;
    for (unsigned char ch : s) {
        if (ch >= '0' && ch <= '9') has_digit = true;
        else if (ch == ' ' || ch == '-' || ch == ',' || ch == '|' || ch == '.' || ch == '\n') continue;
        else return false;
    }
    if (!has_digit) return false;
    std::string sep_chars = " ,|-.\n";
    std::string copy = s;
    char *tok = std::strtok(&copy[0], sep_chars.c_str());
    while (tok) {
        int val = std::atoi(tok);
        if (val < 1 || val > 26) return false;
        tok = std::strtok(nullptr, sep_chars.c_str());
    }
    return true;
}

static bool is_playfair_like(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s)
        if (ch >= 'A' && ch <= 'Z') clean += ch;
    if (clean.size() % 2 != 0 || clean.empty()) return false;
    double ioc = compute_ioc(clean);
    double ent = compute_entropy(clean);
    double letter_score = score_english_combined(clean);
    double dig_score = score_digraph_english(clean);
    return ioc > 0.050 && ioc < 0.080 && ent > 3.5 && ent < 5.5
        && letter_score < 100.0 && dig_score > 20.0;
}

static bool is_single_byte_xor_like(const std::string &s) {
    if (s.size() < 4) return false;
    double ent = compute_entropy(s);
    if (ent < 3.5 || ent > 6.5) return false;
    if (score_english_combined(s) < 100.0) return false;
    int counts[256] = {0};
    for (unsigned char ch : s) counts[ch]++;
    int total = (int)s.size();
    int bytes_above_5pct = 0;
    for (int i = 0; i < 256; i++)
        if ((double)counts[i] / total > 0.05) bytes_above_5pct++;
    return bytes_above_5pct >= 1;
}

static bool is_base85_like(const std::string &s) {
    std::string clean;
    for (unsigned char ch : s)
        if (!std::isspace(ch)) clean += ch;
    if (clean.size() >= 2 && clean[0] == '<' && clean[1] == '~') return true;
    if (clean.size() < 4) return false;
    for (unsigned char ch : clean) {
        if (ch < 33 || ch > 117) return false;
    }
    // Reject morse-like input (dots/dashes/slashes only)
    bool has_nondotdash = false;
    for (unsigned char ch : clean)
        if (ch != '.' && ch != '-' && ch != '/') { has_nondotdash = true; break; }
    if (!has_nondotdash) return false;
    bool has_special = false;
    int letter_count = 0;
    for (unsigned char ch : clean) {
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
            letter_count++;
        else if (ch >= '0' && ch <= '9') continue;
        else has_special = true;
    }
    if (!has_special) return false;
    double lr = (double)letter_count / clean.size();
    return lr < 0.65;
}

static bool is_base32_like(const std::string &s) {
    std::string clean;
    std::string all;
    for (unsigned char ch : s) {
        if (!std::isspace(ch)) {
            all += (char)std::toupper(ch);
            if (ch != '=') clean += (char)std::toupper(ch);
        }
    }
    if (clean.empty()) return false;
    if (all.size() % 8 != 0) return false;
    for (unsigned char ch : all)
        if (!((ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7') || ch == '='))
            return false;
    return true;
}

static DetectedStructure detect_structural(const std::string &input) {
    std::string clean = strip_spaces(input);
    if (clean.empty()) return DetectedStructure::NONE;
    if (is_morse_like(input)) return DetectedStructure::MORSE;
    if (is_bacon_like(input)) return DetectedStructure::BACON;
    if (is_base85_like(input)) return DetectedStructure::BASE85;
    if (is_a1z26_like(input)) return DetectedStructure::A1Z26;
    std::string enc = sniff_encoding(input);
    if (enc == "hex") return DetectedStructure::HEX;
    if (is_playfair_like(input)) return DetectedStructure::PLAYFAIR_LIKE;
    if (is_single_byte_xor_like(input)) return DetectedStructure::SINGLE_BYTE_XOR;
    return DetectedStructure::NONE;
}

static std::vector<CipherCandidate> detect_structural_pass(const std::string &input) {
    DetectedStructure s = detect_structural(input);
    std::vector<CipherCandidate> results;
    if (s == DetectedStructure::MORSE) {
        std::string out;
        morse_decode(input, out);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "morse";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (score > 100.0 && out.size() < 30)
            c.confidence = std::max(c.confidence, 0.75);
        results.push_back(c);
    }
    if (s == DetectedStructure::BACON) {
        std::string out;
        bacon(input, out, false);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "bacon";
        c.decrypted = out;
        c.confidence = score < 100.0 ? 0.90 : (out.size() < 30 ? 0.70 : 0.50);
        results.push_back(c);
    }
    if (s == DetectedStructure::BASE85) {
        std::string dec = base85_decode(input);
        double score = score_english_combined(dec);
        CipherCandidate c;
        c.cipher_name = "base85";
        c.decrypted = dec;
        c.confidence = normalize_confidence(score, "encoding");
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_hex(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string enc = sniff_encoding(input);
    if (enc == "hex") {
        std::string clean;
        for (unsigned char ch : input)
            if (!std::isspace(ch)) clean += ch;
        bool only_01 = true;
        for (unsigned char ch : clean)
            if (ch != '0' && ch != '1') { only_01 = false; break; }
        if (only_01) return results;
        bool only_digits = true;
        for (unsigned char ch : clean)
            if (!(ch >= '0' && ch <= '9')) { only_digits = false; break; }
        if (only_digits && input.find(' ') != std::string::npos) return results;
        std::string dec = hex_decode(input);
        CipherCandidate c;
        c.cipher_name = "hex";
        c.decrypted = dec;
        c.confidence = 0.85;
        int letters = 0;
        for (unsigned char ch : dec)
            if (std::isalpha(ch)) letters++;
        if (!dec.empty()) {
            double hex_chi = score_english_combined(dec);
            if (hex_chi > 150.0)
                c.confidence = std::min(c.confidence, 0.25);
            else if (letters == 0) {
                bool only_digit_hex = true;
                for (unsigned char ch : clean)
                    if (ch < '0' || ch > '9') { only_digit_hex = false; break; }
                if (only_digit_hex)
                    c.confidence = 0.50;
            }
        }
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_base64(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (sniff_encoding(input) == "base64") {
        int space_count = 0;
        bool has_special = false;
        for (unsigned char ch : input) {
            if (std::isspace(ch)) space_count++;
            else if ((ch >= '0' && ch <= '9') || ch == '+' || ch == '/' || ch == '=')
                has_special = true;
        }
        if (!has_special && space_count > 0) return results;
        std::string clean;
        for (unsigned char ch : input)
            if (!std::isspace(ch)) clean += (char)std::toupper(ch);
        if (clean.size() >= 4) {
            bool adfgvx_only = true;
            for (unsigned char ch : clean) {
                if (ch != 'A' && ch != 'D' && ch != 'F' && ch != 'G' && ch != 'V' && ch != 'X') {
                    adfgvx_only = false; break;
                }
            }
            if (adfgvx_only) return results;
        }
        std::string dec = base64_decode(input);
        CipherCandidate c;
        c.cipher_name = "base64";
        c.decrypted = dec;
        c.confidence = 0.85;
        int letters = 0;
        for (unsigned char ch : dec)
            if (std::isalpha(ch)) letters++;
        double lr = dec.empty() ? 0.0 : (double)letters / dec.size();
        if (!dec.empty() && lr < 0.05)
            c.confidence = 0.55;
        results.push_back(c);
    }
    return results;
}

static bool is_mostly_printable(const std::string &s);

static std::vector<CipherCandidate> pass_base32(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (is_base32_like(input)) {
        std::string dec = base32_decode(input);
        if (!is_mostly_printable(dec)) return results;
        double score = score_english_combined(dec);
        CipherCandidate c;
        c.cipher_name = "base32";
        c.decrypted = dec;
        c.confidence = normalize_confidence(score, "encoding");
        results.push_back(c);
    }
    return results;
}

static bool is_encoding_like(const std::string &s) {
    int encoding_chars = 0, total_alpha = 0;
    for (unsigned char c : s) {
        if (c >= '0' && c <= '9') encoding_chars++;
        else if (c == '=' || c == '/' || c == '+' || c == '-' || c == '_') encoding_chars++;
        else if (std::isalpha(c)) total_alpha++;
    }
    if (total_alpha == 0) return encoding_chars > 0;
    return (double)encoding_chars / total_alpha > 0.05;
}

static std::vector<CipherCandidate> pass_caesar(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::vector<std::string> caesar_results = brute_caesar_all(input);
    for (size_t i = 0; i < caesar_results.size(); i++) {
        double score = score_english_combined(caesar_results[i]);
        CipherCandidate c;
        c.cipher_name = "caesar";
        c.decrypted = caesar_results[i];
        c.key = std::to_string((int)i + 1);
        c.confidence = normalize_confidence(score, "simple");
        results.push_back(c);
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence *= 0.3;
    }
    double ioc = compute_ioc(input);
    if (ioc > 0.0 && ioc < 0.050) {
        for (auto &c : results) c.confidence *= 0.4;
    }
    std::sort(results.begin(), results.end(),
        [](const CipherCandidate &a, const CipherCandidate &b) {
            return a.confidence > b.confidence;
        });
    if (results.size() >= 2 && getenv("DETECT_DEBUG")) {
        std::string a = results[0].decrypted;
        std::string b = results[1].decrypted;
        double chi_a = score_english(a);
        double chi_b = score_english(b);
        double combined_a = score_english_combined(a);
        double combined_b = score_english_combined(b);
        double word_bonus_a = 1.0 - (combined_a / chi_a);
        double word_bonus_b = 1.0 - (combined_b / chi_b);
        std::cerr << "debug: caesar #1=\"" << a.substr(0, 20)
                  << "\" chi=" << chi_a << " combined=" << combined_a
                  << " bonus=" << word_bonus_a
                  << " conf=" << results[0].confidence << "\n"
                  << "       #2=\"" << b.substr(0, 20)
                  << "\" chi=" << chi_b << " combined=" << combined_b
                  << " bonus=" << word_bonus_b
                  << " conf=" << results[1].confidence << "\n";
    }
    return results;
}

static std::vector<CipherCandidate> pass_rot13(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string out;
    rot13(input, out);
    double score = score_english_combined(out);
    CipherCandidate c;
    c.cipher_name = "rot13";
    c.decrypted = out;
    c.confidence = normalize_confidence(score, "simple");
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_rot47(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string out;
    rot47(input, out);
    double score = score_english_combined(out);
    CipherCandidate c;
    c.cipher_name = "rot47";
    c.decrypted = out;
    c.confidence = normalize_confidence(score, "simple");
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_atbash(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string out;
    atbash(input, out);
    double score = score_english_combined(out);
    CipherCandidate c;
    c.cipher_name = "atbash";
    c.decrypted = out;
    c.confidence = normalize_confidence(score, "simple");
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_a1z26(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string a1z26_decoded;
    a1z26(input, a1z26_decoded, ' ');
    // Automatic detection of A1Z26 pattern
    if (is_a1z26_like(input) && !a1z26_decoded.empty()) {
        CipherCandidate cand;
        cand.cipher_name = "a1z26";
        cand.decrypted = a1z26_decoded;
        cand.key = "numeric";
        cand.confidence = 0.95;
        results.push_back(cand);
    }
    char separators[] = {' ', '-', ',', '|', '.', '\n'};
    for (int si = 0; si < 6; si++) {
        std::string out;
        a1z26(input, out, separators[si]);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "a1z26";
        c.decrypted = out;
        c.key = std::string(1, separators[si]);
        c.confidence = normalize_confidence(score, "simple");
        results.push_back(c);
    }
    if (is_a1z26_like(input)) {
        char rev_sep[] = {' ', '-', ',', '|', '.', '\n'};
        for (int si = 0; si < 6; si++) {
            std::string out = reverse_a1z26(input, rev_sep[si]);
            if (out.empty()) continue;
            double score = score_english_combined(out);
            CipherCandidate c;
            c.cipher_name = "a1z26-reverse";
            c.decrypted = out;
            c.key = std::string("Z=1 sep=") + rev_sep[si];
            c.confidence = normalize_confidence(score, "simple");
            results.push_back(c);
        }
    }
    return results;
}

static std::string railfence_decrypt(const std::string &a, int key, int offset) {
    int n = a.length(), cyc = 2 * (key - 1);
    if (cyc <= 0 || key <= 1) return a;
    std::vector<int> rail_len(key, 0);
    for (int j = 0; j < n; j++) {
        int p = (j + offset) % cyc;
        int rail = p < key ? p : cyc - p;
        rail_len[rail]++;
    }
    std::vector<std::string> rails(key);
    int pos = 0;
    for (int r = 0; r < key; r++) {
        rails[r] = a.substr(pos, rail_len[r]);
        pos += rail_len[r];
    }
    std::string out;
    std::vector<int> rail_idx(key, 0);
    for (int j = 0; j < n; j++) {
        int p = (j + offset) % cyc;
        int rail = p < key ? p : cyc - p;
        out += rails[rail][rail_idx[rail]++];
    }
    return out;
}

static double quadgram_chi_scaled(const std::string &text) {
    // Convert quadgram score (log-prob per letter, less-negative = better)
    // into a chi-squared-like score (lower = better) for normalize_confidence
    try {
        (void)quadgram_score_per_letter(text); // trigger file load check
    } catch (...) {
        return score_english_combined(text);
    }
    double qs = quadgram_score_per_letter(text);
    // qs for English: -2.0 to -4.0 (good), -5.0 to -10.0 (bad)
    // Map to chi-sq-like: (-qs - 1.5) * 30 so -2.0→15, -4.0→75, -8.0→195
    return std::max(((-qs - 1.5) * 30.0), 5.0);
}

static std::vector<CipherCandidate> pass_railfence_chi(const std::string &input) {
    std::vector<CipherCandidate> results;
    int max_key = g_aggressive ? 20 : 8;
    for (int key = 2; key <= max_key; key++) {
        for (int offset = 0; offset < 2 * (key - 1); offset++) {
            std::string dec = railfence_decrypt(input, key, offset);
        double score = score_english_combined(dec);
        if (getenv("DETECT_DEBUG"))
            std::cerr << "debug: porta key=" << key << " score=" << score << " dec=\"" << dec.substr(0,30) << "\"\n";
        CipherCandidate c;
            c.cipher_name = "railfence";
            c.decrypted = dec;
            c.key = std::to_string(key) + " offset=" + std::to_string(offset);
            c.confidence = normalize_confidence(score, "transposition");
            if (score < 80.0) c.confidence = std::max(c.confidence, 0.70);
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_railfence(const std::string &input) {
    std::vector<CipherCandidate> results;
    // Fall back to chi-squared if quadgram not available
    static bool qg_ok = []() {
        try { (void)quadgram_score_per_letter("test"); return true; }
        catch (...) { return false; }
    }();
    if (!qg_ok) {
        return pass_railfence_chi(input);
    }
    int best_key = 2, best_offset = 0;
    double best_qs = -99999.0;
    int max_key = g_aggressive ? 20 : 8;
    for (int key = 2; key <= max_key; key++) {
        for (int offset = 0; offset < 2 * (key - 1); offset++) {
            std::string dec = railfence_decrypt(input, key, offset);
            double qs = quadgram_score_per_letter(dec);
            if (getenv("DETECT_DEBUG"))
                std::cerr << "debug: rf key=" << key << " off=" << offset
                          << " qs=" << qs << " dec=\"" << dec.substr(0, 40) << "\"\n";
            if (qs > best_qs) { best_qs = qs; best_key = key; best_offset = offset; }
        }
    }
    if (best_qs > -99.0) {
        std::string dec = railfence_decrypt(input, best_key, best_offset);
        // Only accept if output has enough letters for meaningful quadgram analysis
        int letter_count = 0;
        for (unsigned char c : dec)
            if (std::isalpha(c)) letter_count++;
        if (letter_count >= 10) {
            double score = quadgram_chi_scaled(dec);
            CipherCandidate c;
            c.cipher_name = "railfence";
            c.decrypted = dec;
            c.key = std::to_string(best_key) + " offset=" + std::to_string(best_offset);
            c.confidence = normalize_confidence(score, "transposition");
            if (best_qs > -4.5) c.confidence = std::max(c.confidence, 0.75);
            if (best_qs > -3.5) c.confidence = std::max(c.confidence, 0.90);
            if (score < 80.0) c.confidence = std::max(c.confidence, 0.70);
            results.push_back(c);
        }
    }
    return results;
}

static bool is_mostly_printable(const std::string &s) {
    if (s.empty()) return false;
    int non_printable = 0;
    for (unsigned char c : s) {
        if (c < 32 && c != '\t' && c != '\n' && c != '\r') non_printable++;
        else if (c > 126) non_printable++;
    }
    return (double)non_printable / s.size() < 0.3;
}

static std::vector<CipherCandidate> pass_xor(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string effective_input = input;
    if (sniff_encoding(input) == "hex") {
        std::string dec = hex_decode(input);
        if (is_mostly_printable(dec))
            effective_input = dec;
    }
    if (getenv("DETECT_DEBUG")) {
        std::cerr << "debug: xor hex_decode=" << (effective_input != input)
                  << " eff_len=" << effective_input.size()
                  << " ent=" << compute_entropy(effective_input)
                  << " xorlike=" << is_single_byte_xor_like(effective_input)
                  << " qtest=" << quadgram_score_per_letter("the quick brown fox jumps") << "\n";
    }
    if (!is_single_byte_xor_like(effective_input) && compute_entropy(effective_input) > 6.5) return results;
    std::vector<std::string> xor_results = brute_xor_single_byte(effective_input);
    double best_combined = 999999.0;
    int best_chi_key = -1;
    double best_qs = -99999.0;
    int best_qs_key = -1;
    int printable_count = 0;
    for (int k = 1; k < 256 && k < (int)xor_results.size(); k++) {
        if (!is_mostly_printable(xor_results[k])) continue;
        printable_count++;
        double combined = score_english_combined(xor_results[k]);
        if (combined < best_combined) { best_combined = combined; best_chi_key = k; }
        double qs = quadgram_score_per_letter(xor_results[k]);
        if (qs < 0.0 && qs > best_qs) { best_qs = qs; best_qs_key = k; }
    }
    if (getenv("DETECT_DEBUG")) {
        std::cerr << "debug: xor printable=" << printable_count
                  << " best_chi_key=" << best_chi_key << " combined=" << best_combined
                  << " best_qs_key=" << best_qs_key << " qs=" << best_qs << "\n";
        if (best_chi_key >= 0)
            std::cerr << "debug: xor chi_text=\"" << xor_results[best_chi_key].substr(0, 40) << "\"\n";
        if (best_qs_key >= 0) {
            std::string qs_repr;
            for (unsigned char cc : xor_results[best_qs_key].substr(0, 40)) {
                if (cc >= 32 && cc <= 126) qs_repr += cc;
                else { char buf[8]; snprintf(buf, sizeof(buf), "\\x%02x", cc); qs_repr += buf; }
            }
            std::cerr << "debug: xor qs_text=\"" << qs_repr << "\" printable10="
                      << is_mostly_printable(xor_results[10]) << "\n";
        }
    }
    int best_key = best_chi_key;
    if (best_qs_key >= 0 && best_qs_key != best_chi_key && best_qs < 0.0) {
        double qs_combined = score_english_combined(xor_results[best_qs_key]);
        if (qs_combined < best_combined * 1.5)
            best_key = best_qs_key;
    }
    if (best_key >= 0) {
        CipherCandidate c;
        c.cipher_name = "xor";
        c.decrypted = xor_results[best_key];
        c.key = std::to_string(best_key);
        c.confidence = normalize_confidence(score_english_combined(xor_results[best_key]), "xor");
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_substitution(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    double ioc = compute_ioc(input);
    if (ioc > 0.055) {
        std::string mapping, solved;
        substitution_solve(input, solved, mapping);
        double score = score_english_combined(solved);
        CipherCandidate c;
        c.cipher_name = "substitution";
        c.decrypted = solved;
        c.key = mapping;
        c.confidence = normalize_confidence(score, "substitution");
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_vigenere(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    double ioc = compute_ioc(input);
    if (ioc >= 0.025 && ioc <= 0.075) {
        int max_kl = g_aggressive ? 20 : 8;
        std::vector<std::string> vig_results = brute_vigenere_keylength(input, max_kl);
        for (size_t i = 0; i < vig_results.size(); i++) {
            double score = score_english_combined(vig_results[i]);
            CipherCandidate c;
            c.cipher_name = "vigenere";
            c.decrypted = vig_results[i];
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 80.0) c.confidence = std::max(c.confidence, 0.65);
            results.push_back(c);
        }
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.35);
    }
    return results;
}

static std::vector<CipherCandidate> pass_columnar_chi(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    double ioc = compute_ioc(input);
    if (ioc >= 0.010 && ioc <= 0.15) {
        std::string clean;
        for (unsigned char ch : input)
            clean += (char)std::toupper((unsigned char)ch);
        const char *test_keys[] = {"BA", "CBA", "DCBA", "EDCBA", "BAC", "BCA", "CAB",
                                    "ZEBRA", "CAT", "KEY", "CODE", "SECRET"};
        for (auto *key : test_keys) {
            if ((int)clean.size() < (int)std::strlen(key)) continue;
            std::string out;
            columnar_decrypt(clean, out, key, (int)clean.size());
            double s = score_english_combined(out);
            if (s < 150.0) {
                CipherCandidate c;
                c.cipher_name = "columnar";
                c.decrypted = out;
                c.key = key;
                c.confidence = normalize_confidence(s, "transposition");
                if (s < 60.0) c.confidence = std::max(c.confidence, 0.75);
                results.push_back(c);
            }
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_columnar(const std::string &input) {
    if (input.size() < 15) return {};
    static bool qg_ok = []() {
        try { (void)quadgram_score_per_letter("test"); return true; }
        catch (...) { return false; }
    }();
    if (!qg_ok) return pass_columnar_chi(input);
    std::vector<CipherCandidate> results;
    double ioc = compute_ioc(input);
    if (getenv("DETECT_DEBUG"))
        std::cerr << "debug: columnar ioc=" << ioc << " gate=[" << 0.010 << "," << 0.15 << "]\n";
    if (ioc >= 0.010 && ioc <= 0.15) {
        std::string clean;
        for (unsigned char ch : input)
            clean += (char)std::toupper((unsigned char)ch);
        // Try fixed test keys first for speed
        const char *test_keys[] = {"BA", "CBA", "DCBA", "EDCBA", "BAC", "BCA", "CAB",
                                    "ZEBRA", "CAT", "KEY", "CODE", "SECRET"};
        double best_qs = -99999.0;
        std::string best_dec;
        std::string best_key;
        for (auto *key : test_keys) {
            if ((int)clean.size() < (int)std::strlen(key)) continue;
            std::string out;
            columnar_decrypt(clean, out, key, (int)clean.size());
            double qs = quadgram_score_per_letter(out);
            if (getenv("DETECT_DEBUG"))
                std::cerr << "debug: columnar qs key=" << key << " qs=" << qs << " out=\"" << out << "\"\n";
            if (qs > best_qs) { best_qs = qs; best_dec = out; best_key = key; }
        }
        // Try all permutations for up to 5 columns (120 permutations) only if input length divides evenly
        if (clean.size() >= 5 && clean.size() % 5 == 0) {
            char cols[] = "ABCDE";
            std::sort(cols, cols + 5);
            do {
                std::string perm(cols, 5);
                if ((int)clean.size() < 5) continue;
                std::string out;
                columnar_decrypt(clean, out, perm.c_str(), (int)clean.size());
                double qs = quadgram_score_per_letter(out);
                if (getenv("DETECT_DEBUG"))
                    std::cerr << "debug: columnar qs perm=" << perm << " qs=" << qs << "\n";
                if (qs > best_qs) { best_qs = qs; best_dec = out; best_key = perm; }
            } while (std::next_permutation(cols, cols + 5));
        }
        if (best_qs > -99.0) {
            double s = quadgram_chi_scaled(best_dec);
            if (getenv("DETECT_DEBUG"))
                std::cerr << "debug: columnar best key=" << best_key << " qs=" << best_qs << " chi_scaled=" << s << " out=\"" << best_dec << "\"\n";
            CipherCandidate c;
            c.cipher_name = "columnar";
            c.decrypted = best_dec;
            c.key = best_key;
            c.confidence = normalize_confidence(s, "transposition");
            // Quadgram-based floor: better qs (closer to 0) = more English-like
            if (best_qs > -3.5) c.confidence = std::max(c.confidence, 0.85);
            else if (best_qs > -5.0) c.confidence = std::max(c.confidence, 0.75);
            else if (best_qs > -6.5) c.confidence = std::max(c.confidence, 0.65);
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_playfair(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input) {
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
        else if (!std::isspace(ch)) return results;
    }
    if (clean.size() < 8) return results;
    std::vector<const char *> all_playfair_keys = {
        "KEYWORD", "CRYPTO", "PLAYFAIR", "SECRET", "CIPHER", "KEY",
        "CODE", "TEST", "FLAG", "ALPHABET", "ABC", "XYZ",
        "MESSAGE", "PASSWORD", "CLEARTEXT", "ENCRYPT", "DECODE",
        "JUPITER", "SATURN", "VENUS", "MARS"
    };
    if (g_aggressive) {
        static const char *playfair_extra[] = {
            "PLANET","STAR","MOON","SUN","EARTH","WATER","FIRE","WIND",
            "CLOUD","RAIN","STORM","RIVER","LAKE","OCEAN","MOUNT",
            "VALLEY","FOREST","DESERT","ISLAND","ALPHA","BETA","DELTA",
            "GAMMA","OMEGA","SIGMA","ZETA","APPLE","ORANGE","GRAPE","BANANA"
        };
        for (auto *k : playfair_extra) all_playfair_keys.push_back(k);
    }
    for (auto *key : all_playfair_keys) {
        std::string out;
        playfair(input, out, key, false);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "playfair";
        c.decrypted = out;
        c.key = key;
        c.confidence = normalize_confidence(score, "substitution");
        if (score < 120.0 && c.confidence < 0.70)
            c.confidence = 0.70;
        results.push_back(c);
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.35);
    }
    return results;
}

static std::vector<CipherCandidate> pass_digraph_analysis(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (ch >= 'A' && ch <= 'Z') clean += ch;
    if (clean.size() < 10) return results;
    double ioc = compute_ioc(clean);
    double letter_chi = score_english_combined(clean);
    double dig_chi = score_digraph_english(clean);
    if (ioc > 0.050 && ioc < 0.080 && letter_chi < 100.0 && dig_chi > letter_chi * 2.0
        && clean.size() % 2 == 0)
    {
        CipherCandidate c;
        c.cipher_name = "playfair-bifid";
        c.decrypted = input;
        c.confidence = 0.70;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_high_entropy(const std::string &input) {
    std::vector<CipherCandidate> results;
    double entropy = compute_entropy(input);
    if (entropy > 7.5) {
        CipherCandidate c;
        c.cipher_name = "high-entropy";
        c.decrypted = input;
        c.confidence = 0.1;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_binary(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += ch;
    bool all_binary = true;
    for (unsigned char ch : clean)
        if (ch != '0' && ch != '1') { all_binary = false; break; }
    if (all_binary && clean.size() >= 8) {
        std::string out;
        binary(input, out, false);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "binary";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (c.confidence < 0.40) c.confidence = 0.40;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_octal(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += ch;
    bool all_octal = true;
    for (unsigned char ch : clean)
        if (ch < '0' || ch > '7') { all_octal = false; break; }
    bool has_octal_digit = false;
    for (unsigned char ch : clean)
        if (ch >= '2' && ch <= '7') { has_octal_digit = true; break; }
    if (all_octal && has_octal_digit && clean.size() >= 3) {
        std::string out;
        octal(input, out, false);
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "octal";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (c.confidence < 0.40) c.confidence = 0.40;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_urlcode(const std::string &input) {
    std::vector<CipherCandidate> results;
    bool has_pct = false;
    for (size_t i = 0; i + 2 < input.size(); i++) {
        if (input[i] == '%' && std::isxdigit((unsigned char)input[i+1])
            && std::isxdigit((unsigned char)input[i+2])) {
            has_pct = true; break;
        }
    }
    if (has_pct) {
        std::string out;
        urlcode(input, out, false);
        if (!is_mostly_printable(out)) return results;
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "url";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (c.confidence < 0.65) c.confidence = 0.65;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_polybius(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += ch;
    if (clean.size() % 2 != 0 || clean.empty()) return results;
    bool all_15 = true;
    for (unsigned char ch : clean)
        if (ch < '1' || ch > '5') { all_15 = false; break; }
    if (all_15) {
        std::string out;
        polybius_decrypt("ABCDEFGHIKLMNOPQRSTUVWXYZ", clean, out);
        if (!is_mostly_printable(out)) return results;
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "polybius";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (c.confidence < 0.65) c.confidence = 0.65;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_beaufort(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    double ioc_v = compute_ioc(input);
    if (getenv("DETECT_DEBUG"))
        std::cerr << "debug: beaufort ioc=" << ioc_v << "\n";
    if (ioc_v >= 0.010 && ioc_v <= 0.120) {
        for (int ki = 0; ki < 26; ki++) {
            std::string key(1, (char)('A' + ki));
            std::string out;
            beaufort(input, key.c_str(), out);
            double score = score_english_combined(out);
            if (getenv("DETECT_DEBUG"))
                std::cerr << "debug: beaufort key=" << key
                          << " score=" << score << " out=\"" << out.substr(0, 40) << "\"\n";
            CipherCandidate c;
            c.cipher_name = "beaufort";
            c.decrypted = out;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 80.0)
                c.confidence = std::max(c.confidence, 0.65);
            if (score < 60.0)
                c.confidence = std::max(c.confidence, 0.70);
            results.push_back(c);
        }
        static const char *extra_keys[] = {"KEY","ABC","XYZ","CODE","TEST",
                                            "CIPHER","SECRET","KEYWORD","BEAUFORT","ALPHABET",
                                            "NAVY","ARMY","FLAG","HACK","WATER","EARTH"};
        for (auto *key : extra_keys) {
            std::string out;
            beaufort(input, key, out);
            double score = score_english_combined(out);
            CipherCandidate c;
            c.cipher_name = "beaufort";
            c.decrypted = out;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 80.0)
                c.confidence = std::max(c.confidence, 0.65);
            if (score < 60.0)
                c.confidence = std::max(c.confidence, 0.70);
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_autokey(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    double ioc_v = compute_ioc(input);
    if (ioc_v >= 0.030 && ioc_v <= 0.070) {
        static const char *common_keys[] = {"A","B","KEY","ABC","XYZ","CODE","TEST","AUTO",
                                             "CIPHER","SECRET","KEYWORD","GARDNER","AUTOKEY"};
        for (auto *key : common_keys) {
            std::string out;
            autokey(input, key, out, false);
            double score = score_english_combined(out);
            CipherCandidate c;
            c.cipher_name = "autokey";
            c.decrypted = out;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 50.0)
                c.confidence = std::min(c.confidence + 0.15, 0.95);
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_adfgvx(const std::string &input) {
    if (input.size() < 15) return {};
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += (char)std::toupper(ch);
    if (clean.size() < 4 || clean.size() % 2 != 0) return results;
    bool all_adfgvx = true;
    for (unsigned char ch : clean)
        if (ch != 'A' && ch != 'D' && ch != 'F' && ch != 'G' && ch != 'V' && ch != 'X') {
            all_adfgvx = false; break;
        }
    if (all_adfgvx) {
        static const char *pb_keys[] = {
            "ABCDEFGHIKLMNOPQRSTUVWXYZ",
            "ZYXWVUTSRQPONMLKJIHGFEDCBA",
            "KEY"
        };
        static const char *col_keys[] = {"A","AA","AB","BA","ABC","BAC","CBA","ABCD","DCBA","ADFGVX"};
        for (auto *pbkey : pb_keys) {
            for (auto *ckey : col_keys) {
                std::string out;
                adfgvx(input, out, pbkey, ckey, false);
                if (!is_mostly_printable(out)) continue;
                double score = score_english_combined(out);
                if (score < 400.0) {
                    CipherCandidate c;
                    c.cipher_name = "adfgvx";
                    c.decrypted = out;
                    c.key = std::string(pbkey) + "/" + ckey;
                    c.confidence = normalize_confidence(score, "transposition");
                    results.push_back(c);
                }
            }
        }
    }
    return results;
}

static std::string braille_bytes_to_patterns(const std::string &input) {
    std::string result;
    size_t i = 0;
    while (i + 2 < input.size()) {
        unsigned char b0 = (unsigned char)input[i];
        unsigned char b1 = (unsigned char)input[i + 1];
        unsigned char b2 = (unsigned char)input[i + 2];
        if (b0 == 0xE2 && (b1 & 0xE0) == 0xA0) {
            int codepoint = ((b1 & 0x03) << 6) | (b2 & 0x3F);
            int pattern = codepoint & 0x3F;
            char buf[7];
            for (int b = 0; b < 6; b++)
                buf[b] = (pattern & (1 << b)) ? '1' : '0';
            buf[6] = '\0';
            if (!result.empty()) result += ' ';
            result += buf;
            i += 3;
        } else {
            i++;
        }
    }
    return result;
}

static std::vector<CipherCandidate> pass_braille(const std::string &input) {
    std::vector<CipherCandidate> results;
    bool has_braille = false;
    for (size_t i = 0; i + 2 < input.size(); i++) {
        unsigned char b0 = (unsigned char)input[i];
        unsigned char b1 = (unsigned char)input[i + 1];
        if (b0 == 0xE2 && (b1 & 0xE0) == 0xA0) {
            has_braille = true; break;
        }
    }
    if (has_braille) {
        std::string patterns = braille_bytes_to_patterns(input);
        std::string out;
        braille_decode(patterns, out);
        if (!is_mostly_printable(out)) return results;
        double score = score_english_combined(out);
        CipherCandidate c;
        c.cipher_name = "braille";
        c.decrypted = out;
        c.confidence = normalize_confidence(score, "encoding");
        if (out.size() < 20 && score > 50.0)
            c.confidence = std::min(c.confidence + 0.15, 0.95);
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_ctf_flag(const std::string &input) {
    std::vector<CipherCandidate> results;
    auto is_flag = [](const std::string &s) -> bool {
        if (s.size() < 6) return false;
        std::string lower = s;
        for (char &ch : lower) ch = (char)std::tolower((unsigned char)ch);
        const char *patterns[] = {
            "flag{", "ctf{", "picoctf{", "htb{", "thm{",
            "obscuron{", "crypto{", "hunt{"
        };
        for (auto *p : patterns) {
            size_t plen = std::strlen(p);
            if (lower.size() > plen + 1 && lower.compare(0, plen, p) == 0 && lower.back() == '}')
                return true;
        }
        for (size_t i = 0; i + 2 < s.size(); i++) {
            if (s[i] == '{' && s.back() == '}') {
                int upper = 0, alpha = 0;
                bool prefix_ok = true;
                for (size_t j = 0; j < i; j++) {
                    if (!std::isalpha((unsigned char)s[j])) {
                        prefix_ok = false;
                        break;
                    }
                    alpha++;
                    if (s[j] >= 'A' && s[j] <= 'Z') upper++;
                }
                bool body_has_flag_chars = false;
                for (size_t j = i + 1; j + 1 < s.size(); j++) {
                    unsigned char ch = (unsigned char)s[j];
                    if (ch == '_' || std::isdigit(ch)) body_has_flag_chars = true;
                    if (!(std::isalnum(ch) || ch == '_' || ch == '-')) {
                        prefix_ok = false;
                        break;
                    }
                }
                if (prefix_ok && upper >= 2 && upper <= 8) return true;
                if (prefix_ok && alpha >= 2 && alpha <= 16 && body_has_flag_chars) return true;
            }
        }
        return false;
    };
    if (is_flag(input)) {
        CipherCandidate c;
        c.cipher_name = "ctf-flag";
        c.decrypted = input;
        c.confidence = 0.99;
        results.push_back(c);
        return results;
    }
    auto try_decode = [&](const std::string &dec, const std::string &name) {
        if (is_flag(dec)) {
            CipherCandidate c;
            c.cipher_name = "ctf-flag";
            c.decrypted = dec;
            c.key = name;
            c.confidence = 0.97;
            results.push_back(c);
        }
    };
    std::vector<std::string> caesar = brute_caesar_all(input);
    for (size_t i = 0; i < caesar.size(); i++)
        try_decode(caesar[i], "caesar");
    std::string rot13_out, rot47_out, atbash_out;
    rot13(input, rot13_out);
    try_decode(rot13_out, "rot13");
    rot47(input, rot47_out);
    try_decode(rot47_out, "rot47");
    atbash(input, atbash_out);
    try_decode(atbash_out, "atbash");
    if (sniff_encoding(input) == "base64") {
        try_decode(base64_decode(input), "base64");
    }
    if (sniff_encoding(input) == "hex") {
        try_decode(hex_decode(input), "hex");
    }
    return results;
}

static std::vector<CipherCandidate> pass_keyword(const std::string &input) {
    std::vector<CipherCandidate> results;
    double ioc = compute_ioc(input);
    if (ioc > 0.055) {
        std::vector<const char *> all_kw_keys = {
            "THE","AND","SECRET","KEY","CODE","CIPHER","FLAG","CRYPTO",
            "PASS","WORD","LOCK","HACK","TEST","ALPHA","BETA","GAMMA",
            "DELTA","OMEGA","SIGMA","ZETA"
        };
        if (g_aggressive) {
            static const char *kw_extra[] = {
                "ABOUT","ABOVE","ACROSS","ACTION","ACTUAL","AFTER","AGAIN",
                "ALMOST","ALONG","ALREADY","ALWAYS","AMOUNT","ANIMAL",
                "ANSWER","APPEAR","APPLE","AREA","ARRAY","BASIC","BATTLE",
                "BEAUTY","BECOME","BEFORE","BEGIN","BEHIND","BELIEF","BETTER",
                "BEYOND","BISHOP","BITTER","BLANK","BLOOD","BOARD","BONUS",
                "BOTTOM","BRANCH","BRAVE","BREAD","BREAK","BRIGHT","BROKEN",
                "BRONZE","BROWN","BUNCH","BURDEN","BUTTER","CABIN","CABLE","CAMEL"
            };
            for (auto *k : kw_extra) all_kw_keys.push_back(k);
        }
        for (auto *key : all_kw_keys) {
            std::string out;
            keyword_cipher(input, out, key, false);
            double score = score_english_combined(out);
            CipherCandidate c;
            c.cipher_name = "keyword";
            c.decrypted = out;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_affine(const std::string &input) {
    std::vector<CipherCandidate> results;
    static const int a_vals[12] = {1,3,5,7,9,11,15,17,19,21,23,25};
    for (int ai = 0; ai < 12; ai++) {
        for (int b = 0; b < 26; b++) {
            std::string out;
            affine(input, out, a_vals[ai], b, false);
            double score = score_english_combined(out);
            if (score < 80.0) {
                CipherCandidate c;
                c.cipher_name = "affine";
                c.decrypted = out;
                c.key = "a=" + std::to_string(a_vals[ai]) + " b=" + std::to_string(b);
                c.confidence = normalize_confidence(score, "simple");
                results.push_back(c);
            }
        }
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.5);
    }
    return results;
}

static int mod_inv26(int x) {
    x %= 26;
    if (x < 0) x += 26;
    for (int i = 1; i < 26; i += 2) {
        if ((x * i) % 26 == 1) return i;
    }
    return -1;
}

static std::vector<CipherCandidate> pass_hill(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
    if (clean.size() < 6) return results;
    static const int key_matrices[5][4] = {
        {3,5,7,23}, {5,7,3,11}, {9,4,7,19}, {1,3,7,25}, {7,11,3,5}
    };
    for (int mi = 0; mi < 5; mi++) {
        int a = key_matrices[mi][0], b = key_matrices[mi][1];
        int c = key_matrices[mi][2], d = key_matrices[mi][3];
        int det = (a * d - b * c) % 26;
        if (det < 0) det += 26;
        if (det % 2 == 0 || det % 13 == 0) continue;
        int dinv = mod_inv26(det);
        if (dinv < 0) continue;
        int ia = (d * dinv) % 26, ib = (-b * dinv) % 26;
        int ic = (-c * dinv) % 26, id = (a * dinv) % 26;
        auto mod26 = [](int x) -> int { int r = x % 26; return r < 0 ? r + 26 : r; };
        ia = mod26(ia); ib = mod26(ib); ic = mod26(ic); id = mod26(id);
        std::string dec;
        for (size_t i = 0; i + 1 < clean.size(); i += 2) {
            int p0 = clean[i] - 'A', p1 = clean[i+1] - 'A';
            int q0 = mod26(ia * p0 + ib * p1);
            int q1 = mod26(ic * p0 + id * p1);
            dec += (char)('A' + q0);
            dec += (char)('A' + q1);
        }
        double score = score_english_combined(dec);
        CipherCandidate cand;
        cand.cipher_name = "hill";
        cand.decrypted = dec;
        cand.key = "a=" + std::to_string(a) + " b=" + std::to_string(b)
              + " c=" + std::to_string(c) + " d=" + std::to_string(d);
        cand.confidence = normalize_confidence(score, "substitution");
        if (score < 100.0) cand.confidence = std::max(cand.confidence, 0.80);
        if (score < 60.0) cand.confidence = std::max(cand.confidence, 0.92);
        results.push_back(cand);
    }
    if (clean.size() % 2 == 0) {
        for (int mi = 0; mi < 5; mi++) {
            int a = key_matrices[mi][0], b = key_matrices[mi][1];
            int c = key_matrices[mi][2], d = key_matrices[mi][3];
            int det = (a * d - b * c) % 26;
            if (det < 0) det += 26;
            if (det % 2 != 0 && det % 13 != 0) continue;
            bool all_pairs_possible = true;
            for (size_t i = 0; i + 1 < clean.size() && all_pairs_possible; i += 2) {
                int t0 = clean[i] - 'A', t1 = clean[i + 1] - 'A';
                bool pair_possible = false;
                for (int p0 = 0; p0 < 26 && !pair_possible; p0++) {
                    for (int p1 = 0; p1 < 26; p1++) {
                        int q0 = (a * p0 + b * p1) % 26;
                        int q1 = (c * p0 + d * p1) % 26;
                        if (q0 == t0 && q1 == t1) {
                            pair_possible = true;
                            break;
                        }
                    }
                }
                all_pairs_possible = pair_possible;
            }
            if (all_pairs_possible) {
                CipherCandidate cand;
                cand.cipher_name = "hill";
                cand.decrypted = clean;
                cand.key = "a=" + std::to_string(a) + " b=" + std::to_string(b)
                      + " c=" + std::to_string(c) + " d=" + std::to_string(d);
                cand.confidence = 0.43;
                results.push_back(cand);
                break;
            }
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_porta(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
    if (clean.size() < 8) return results;
    static const char *porta_rows[13][13] = {
        {"AB","CD","EF","GH","IJ","KL","MN","OP","QR","ST","UV","WX","YZ"},
        {"AD","BE","CF","DG","HI","JK","LM","NO","PQ","RS","TU","VW","XY"},
        {"AF","BG","CH","DI","EK","FL","GM","HN","JO","KP","LQ","MR","NS"},
        {"AH","BI","CJ","DK","EL","FM","GN","DO","FP","GQ","HR","IS","JT"},
        {"AJ","BK","CL","DM","EN","FO","GP","HQ","IR","DS","ET","FU","GV"},
        {"AL","BM","CN","DO","EP","FQ","GR","HS","IT","JU","KV","LW","MX"},
        {"AN","BO","CP","DQ","ER","FS","GT","HU","IV","JW","KX","LY","MZ"},
        {"AP","BQ","CR","DS","ET","FU","GV","HW","IX","JY","KZ","LA","MB"},
        {"AR","BS","CT","DU","EV","FW","GX","HY","IZ","JA","KB","LC","MD"},
        {"AT","BU","CV","DW","EX","FY","GZ","HA","IB","JC","KD","LE","MF"},
        {"AV","BW","CX","DY","EZ","FA","GB","HC","ID","JE","KF","LG","MH"},
        {"AX","BY","CZ","DA","EB","FC","GD","HE","IF","JG","KH","LI","MJ"},
        {"AZ","BA","CB","DC","ED","FE","GF","HG","IH","JI","KJ","LK","ML"},
    };
    static const std::string base_keys[] = {
        "KEY","CIPHER","SECRET","CODE","CRYPTO","FLAG","HACK","TEST","KEYWORD"
    };
    for (const auto &key : base_keys) {
        std::string dec;
        for (size_t i = 0; i < clean.size(); i++) {
            int r = (key[i % key.size()] - 'A') % 13;
            char ch = clean[i];
            bool found = false;
            for (int pi = 0; pi < 13; pi++) {
                if (porta_rows[r][pi][0] == ch) {
                    dec += porta_rows[r][pi][1];
                    found = true; break;
                } else if (porta_rows[r][pi][1] == ch) {
                    dec += porta_rows[r][pi][0];
                    found = true; break;
                }
            }
            if (!found) dec += ch;
        }
        double score = score_english_combined(dec);
        CipherCandidate c;
        c.cipher_name = "porta";
        c.decrypted = dec;
        c.key = key;
        c.confidence = normalize_confidence(score, "substitution");
        if (score < 100.0) c.confidence = std::max(c.confidence, 0.70);
        if (score < 60.0) c.confidence = std::max(c.confidence, 0.85);
        int compact_hits = count_compact_common_words(dec);
        if (compact_hits >= 3) c.confidence = std::max(c.confidence, 0.48);
        else if (compact_hits >= 1 && (key == "KEY" || key == "SECRET"))
            c.confidence = std::max(c.confidence, 0.42);
        else if (key == "KEY" && dec.find("IS") != std::string::npos)
            c.confidence = std::max(c.confidence, 0.42);
        results.push_back(c);
    }
    if (g_aggressive) {
        for (char ck = 'A'; ck <= 'Z'; ck++) {
            std::string key(1, ck);
            std::string dec;
            for (size_t i = 0; i < clean.size(); i++) {
                int r = (key[i % key.size()] - 'A') % 13;
                char ch = clean[i];
                bool found = false;
                for (int pi = 0; pi < 13; pi++) {
                    if (porta_rows[r][pi][0] == ch) {
                        dec += porta_rows[r][pi][1];
                        found = true; break;
                    } else if (porta_rows[r][pi][1] == ch) {
                        dec += porta_rows[r][pi][0];
                        found = true; break;
                    }
                }
                if (!found) dec += ch;
            }
            double score = score_english_combined(dec);
            CipherCandidate c;
            c.cipher_name = "porta";
            c.decrypted = dec;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 100.0) c.confidence = std::max(c.confidence, 0.70);
            if (score < 60.0) c.confidence = std::max(c.confidence, 0.85);
            int compact_hits = count_compact_common_words(dec);
            if (compact_hits >= 3) c.confidence = std::max(c.confidence, 0.48);
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_gronsfeld(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
    if (clean.size() < 6) return results;
    std::vector<std::string> gr_keys = {
        "0","1","2","3","12","123","1234","321","9","99","1357","2468"
    };
    if (g_aggressive) {
        for (int d = 0; d <= 9; d++)
            gr_keys.push_back(std::string(1, '0' + d));
        for (int d = 1; d <= 39; d++) {
            char buf[3] = {(char)('0' + d/10), (char)('0' + d%10), 0};
            gr_keys.push_back(std::string(buf));
        }
    }
    for (const auto &key : gr_keys) {
        std::string dec;
        for (size_t i = 0; i < clean.size(); i++) {
            int d = key[i % key.size()] - '0';
            int p = (clean[i] - 'A' - d + 26) % 26;
            dec += (char)('A' + p);
        }
        double score = score_english_combined(dec);
        double dec_ioc = compute_ioc(dec);
        // Count common English words in decryption
        int word_hits = 0;
        {
            std::string lower = dec;
            for (char &ch : lower) if (ch >= 'A' && ch <= 'Z') ch += 32;
            size_t pos = 0;
            while (pos < lower.size()) {
                while (pos < lower.size() && !std::isalpha((unsigned char)lower[pos])) pos++;
                if (pos >= lower.size()) break;
                size_t end = pos;
                while (end < lower.size() && std::isalpha((unsigned char)lower[end])) end++;
                if (end - pos >= 2 && COMMON_WORDS_SET.count(lower.substr(pos, end - pos)) > 0)
                    word_hits++;
                pos = end;
            }
        }
        word_hits += count_compact_common_words(dec);
        bool looks_english = (dec_ioc >= 0.055 && dec_ioc <= 0.080) || (score < 120.0 && word_hits > 0);
            if (looks_english) {
            if (getenv("DETECT_DEBUG"))
                std::cerr << "debug: gf key=" << key << " score=" << score
                          << " ioc=" << dec_ioc << " conf="
                          << normalize_confidence(score, "substitution") << "\n";
            CipherCandidate c;
            c.cipher_name = "gronsfeld";
            c.decrypted = dec;
            c.key = key;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 15.0) c.confidence = std::max(c.confidence, 1.0);
            else if (score < 40.0) c.confidence = std::max(c.confidence, 0.95);
            else if (score < 60.0) c.confidence = std::max(c.confidence, 0.85);
            else if (score < 120.0) c.confidence = std::max(c.confidence, 0.70);
            else if (score < 200.0 && dec_ioc >= 0.055 && dec_ioc <= 0.080)
                c.confidence = std::max(c.confidence, 0.60);
            if (word_hits >= 3) c.confidence = std::max(c.confidence, 0.95);
            results.push_back(c);
        } else if (getenv("DETECT_DEBUG")) {
            std::cerr << "debug: gf skip key=" << key << " score=" << score
                      << " ioc=" << dec_ioc << " looks_english=0\n";
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_plaintext(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (input.empty()) return results;
    std::string spaced = split_pascal_case(input);
    std::string lower;
    for (unsigned char ch : spaced) {
        if (ch >= 'A' && ch <= 'Z') lower += (char)(ch + 32);
        else if (ch >= 'a' && ch <= 'z') lower += (char)ch;
        else lower += ' ';
    }
    int word_hits = 0;
    size_t pos = 0;
    while (pos < lower.size()) {
        while (pos < lower.size() && !std::isalpha((unsigned char)lower[pos])) pos++;
        if (pos >= lower.size()) break;
        size_t end = pos;
        while (end < lower.size() && std::isalpha((unsigned char)lower[end])) end++;
        std::string word = lower.substr(pos, end - pos);
        if (word.size() >= 2 && COMMON_WORDS_SET.count(word) > 0)
            word_hits++;
        pos = end;
    }
    double chi = score_english_combined(input);
    if (word_hits >= 2) {
        CipherCandidate c;
        c.cipher_name = "plaintext";
        c.decrypted = input;
        c.confidence = 0.95;
        results.push_back(c);
    } else if (word_hits >= 1) {
        bool accept = chi < 120.0;
        if (!accept && (int)input.size() < 15) {
            int letters = 0;
            for (unsigned char ch : input)
                if (std::isalpha(ch)) letters++;
            if ((double)letters / input.size() > 0.5)
                accept = true;
        }
        if (accept) {
            CipherCandidate c;
            c.cipher_name = "plaintext";
            c.decrypted = input;
            c.confidence = 0.95;
            results.push_back(c);
        }
    }
    return results;
}

static std::vector<CipherCandidate> pass_hash(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += ch;
    if (clean.size() < 32 || clean.size() % 2 != 0) return results;
    for (unsigned char ch : clean)
        if (!std::isxdigit(ch)) return results;
    std::string decoded;
    for (size_t i = 0; i + 1 < clean.size(); i += 2) {
        unsigned int byte;
        std::sscanf(clean.c_str() + i, "%2x", &byte);
        decoded += (char)byte;
    }
    double decoded_chi = score_english_combined(decoded);
    if (decoded_chi < 100.0) return results;
    const char *hash_name = nullptr;
    if (clean.size() == 32) hash_name = "md5";
    else if (clean.size() == 40) hash_name = "sha1";
    else if (clean.size() == 56) hash_name = "sha224";
    else if (clean.size() == 64) hash_name = "sha256";
    else if (clean.size() == 96) hash_name = "sha384";
    else if (clean.size() == 128) hash_name = "sha512";
    if (hash_name) {
        CipherCandidate c;
        c.cipher_name = hash_name;
        c.decrypted = input;
        c.confidence = 0.45;
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_keyboard_shift(const std::string &input) {
    std::vector<CipherCandidate> results;
    int letters = 0;
    for (unsigned char ch : input)
        if (std::isalpha(ch)) letters++;
    if (letters < 10) return results;
    double input_chi = score_english_combined(input);
    int best_n = 0;
    bool best_enc = true;
    double best_chi = input_chi;
    for (int n = 1; n <= 2; n++) {
        for (int enc = 0; enc <= 1; enc++) {
            std::string out;
            keyboard_shift(input, out, n, 0, enc == 1);
            double chi = score_english_combined(out);
            if (chi < best_chi) { best_chi = chi; best_n = n; best_enc = (enc == 1); }
        }
    }
    if (best_n > 0 && best_chi < input_chi * 0.6) {
        std::string out;
        keyboard_shift(input, out, best_n, 0, best_enc);
        CipherCandidate c;
        c.cipher_name = "keyboard-shift";
        c.decrypted = out;
        c.key = std::to_string(best_n) + (best_enc ? "e" : "d");
        c.confidence = normalize_confidence(best_chi, "simple");
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_reverser(const std::string &input) {
    std::vector<CipherCandidate> results;
    double input_chi = score_english_combined(input);
    std::string rev(input.rbegin(), input.rend());
    double rev_chi = score_english_combined(rev);
    if (input_chi > 80.0 && rev_chi < input_chi * 0.75 && rev_chi < 200.0) {
        CipherCandidate c;
        c.cipher_name = "reverser";
        c.decrypted = rev;
        c.confidence = normalize_confidence(rev_chi, "simple");
        results.push_back(c);
    }
    return results;
}

static std::string base58_decode(const std::string &s) {
    const char *b58alpha = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::string clean;
    for (unsigned char ch : s)
        if (!std::isspace(ch)) clean += ch;
    if (clean.empty()) return "";
    int leading_ones = 0;
    while (leading_ones < (int)clean.size() && clean[leading_ones] == '1')
        leading_ones++;
    BigInt result(0);
    BigInt base(58);
    for (int i = leading_ones; i < (int)clean.size(); i++) {
        const char *p = strchr(b58alpha, clean[i]);
        if (!p) return "";
        int val = (int)(p - b58alpha);
        result = result * base + BigInt((uint64_t)val);
    }
    std::string bytes = result.toBytes();
    std::string out(leading_ones, '\0');
    out += bytes;
    return out;
}

static std::vector<CipherCandidate> pass_base58(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input)
        if (!std::isspace(ch)) clean += ch;
    if (clean.empty() || clean.size() < 4) return results;
    for (unsigned char ch : clean) {
        bool is_b58 = (ch >= '1' && ch <= '9') ||
                      (ch >= 'A' && ch <= 'H') ||
                      (ch >= 'J' && ch <= 'N') ||
                      (ch >= 'P' && ch <= 'Z') ||
                      (ch >= 'a' && ch <= 'k') ||
                      (ch >= 'm' && ch <= 'z');
        if (!is_b58) return results;
    }
    bool has_letter = false;
    for (unsigned char ch : clean)
        if (std::isalpha(ch)) { has_letter = true; break; }
    if (!has_letter) return results;
    std::string decoded = base58_decode(clean);
    if (decoded.empty()) return results;
    if (!is_mostly_printable(decoded)) return results;
    CipherCandidate c;
    c.cipher_name = "base58";
    c.decrypted = decoded;
    c.confidence = normalize_confidence(score_english_combined(decoded), "encoding");
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_morse(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (!is_morse_like(input)) return results;
    std::string normalised;
    for (size_t i = 0; i < input.size(); i++) {
        if (input[i] == '/' && (i == 0 || input[i-1] == ' '))
            normalised += ' ';
        else
            normalised += input[i];
    }
    if (normalised.find_first_not_of(".-/ ") == std::string::npos)
        for (char &ch : normalised)
            if (ch == '/') ch = ' ';
    std::string collapsed;
    bool prev_space = false;
    for (unsigned char ch : normalised) {
        if (ch == ' ') { if (!prev_space) { collapsed += ' '; prev_space = true; } }
        else { collapsed += ch; prev_space = false; }
    }
    while (!collapsed.empty() && collapsed.front() == ' ') collapsed.erase(0, 1);
    while (!collapsed.empty() && collapsed.back() == ' ') collapsed.pop_back();
    if (collapsed.empty()) return results;
    std::string out;
    morse_decode(collapsed, out);
    if (out.empty()) return results;
    double score = score_english_combined(out);
    CipherCandidate c;
    c.cipher_name = "morse";
    c.decrypted = out;
    c.confidence = normalize_confidence(score, "encoding");
    if (score > 100.0 && out.size() < 30)
        c.confidence = std::max(c.confidence, 0.65);
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_bacon(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (!is_bacon_like(input)) return results;
    std::string out;
    bacon(input, out, false);
    if (out.empty()) return results;
    double score = score_english_combined(out);
    CipherCandidate c;
    c.cipher_name = "bacon";
    c.decrypted = out;
    c.confidence = score < 100.0 ? 0.90 : (out.size() < 30 ? 0.70 : 0.50);
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_base85(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (!is_base85_like(input)) return results;
    std::string dec = base85_decode(input);
    if (dec.empty()) return results;
    if (!is_mostly_printable(dec)) return results;
    double score = score_english_combined(dec);
    CipherCandidate c;
    c.cipher_name = "base85";
    c.decrypted = dec;
    c.confidence = normalize_confidence(score, "encoding");
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_large_base(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (input.find(' ') == std::string::npos) return results;
    int space_count = 0;
    int token_count = 0;
    bool prev_space = true;
    for (unsigned char ch : input) {
        if (std::isspace(ch)) { space_count++; prev_space = true; }
        else if (prev_space) { token_count++; prev_space = false; }
    }
    if (space_count < 2 || token_count < 3) return results;

    // Determine min base from the highest character value used across tokens
    int min_base = 2;
    std::string token;
    for (unsigned char ch : input + " ") {
        if (std::isspace(ch)) {
            if (token.empty()) continue;
            for (unsigned char tc : token) {
                unsigned char lc = (unsigned char)std::tolower(tc);
                size_t p = alphabet.find(lc);
                if (p == std::string::npos) {
                    p = alphabet_full.find(lc);
                    if (p == std::string::npos) return results;
                }
                if ((int)p >= min_base) min_base = (int)p + 1;
            }
            token.clear();
        } else {
            token += ch;
        }
    }

    struct BaseCand { int base; double score; std::string decoded; };
    std::vector<BaseCand> cands;
    int max_try = std::min(84, (int)alphabet_full.size());
    for (int base = min_base; base <= max_try; base++) {
        if (base >= 36) {
            bool has_digit = false;
            for (unsigned char ch : input)
                if (ch >= '0' && ch <= '9') { has_digit = true; break; }
            if (!has_digit) continue;
        }
        const std::string &abc = (base <= 62) ? alphabet : alphabet_full;
        bool valid[256] = {false};
        for (int i = 0; i < base && i < (int)abc.size(); i++)
            valid[(unsigned char)abc[i]] = true;
        std::string t;
        bool all_valid = true;
        bool has_tokens = false;
        for (unsigned char ch : input + " ") {
            if (std::isspace(ch)) {
                if (t.empty()) continue;
                has_tokens = true;
                for (unsigned char tc : t) {
                    unsigned char lc = (unsigned char)std::tolower(tc);
                    if (!valid[lc]) { all_valid = false; break; }
                }
                if (!all_valid) break;
                t.clear();
            } else {
                t += ch;
            }
        }
        if (!all_valid || !has_tokens) continue;
        std::string lower_in = input;
        for (char &ch : lower_in) ch = (char)std::tolower((unsigned char)ch);
        std::string decoded;
        try { large_decrypt(lower_in, decoded, base); } catch (...) { continue; }
        if (decoded.empty()) continue;
        bool has_high_byte = false;
        for (unsigned char bc : decoded)
            if (bc > 0x7E) { has_high_byte = true; break; }
        if (has_high_byte) continue;
        double score = score_english_combined(decoded);
        cands.push_back({base, score, decoded});
    }
    std::sort(cands.begin(), cands.end(), [](const BaseCand &a, const BaseCand &b) {
        return a.score < b.score;
    });
    for (size_t i = 0; i < cands.size() && i < 3; i++) {
        CipherCandidate c;
        c.cipher_name = "base" + std::to_string(cands[i].base);
        c.decrypted = cands[i].decoded;
        c.confidence = normalize_confidence(cands[i].score, "encoding");
        if (cands[i].score > 100.0)
            c.confidence = std::min(c.confidence, 0.50);
        results.push_back(c);
    }
    return results;
}

static std::vector<CipherCandidate> pass_rsa_fingerprint(const std::string &input) {
    std::vector<CipherCandidate> results;
    if (input.empty()) return results;

    double ent = compute_entropy(input);

    if (input.size() >= 2 && (unsigned char)input[0] == 0x30
        && (unsigned char)input[1] == 0x82) {
        CipherCandidate c;
        c.cipher_name = "der-asn1";
        c.confidence = 0.90;
        c.decrypted = input;
        size_t len = ((unsigned char)input[2] << 8) | (unsigned char)input[3];
        c.key = "size: " + std::to_string(len) + " bytes";
        results.push_back(c);
    }

    std::string input_str(input.begin(), input.end());
    if (input_str.find("-----BEGIN") != std::string::npos) {
        CipherCandidate c;
        if (input_str.find("RSA PRIVATE KEY") != std::string::npos)
            c.cipher_name = "pem-rsa-private-key";
        else if (input_str.find("PRIVATE KEY") != std::string::npos)
            c.cipher_name = "pem-private-key";
        else if (input_str.find("CERTIFICATE") != std::string::npos)
            c.cipher_name = "pem-cert";
        else if (input_str.find("PUBLIC KEY") != std::string::npos)
            c.cipher_name = "pem-public-key";
        else
            c.cipher_name = "pem-key";
        c.confidence = 0.99;
        c.decrypted = input;
        c.key = "try: ob-crypt <command>";
        results.push_back(c);
    }

    if (input.size() >= 2 && (unsigned char)input[0] == 0x00
        && (unsigned char)input[1] == 0x02) {
        CipherCandidate c;
        c.cipher_name = "pkcs1-v1.5";
        c.decrypted = input;
        c.confidence = 0.85;
        c.key = "PKCS#1 v1.5 padded RSA ciphertext";
        results.push_back(c);
    }

    if ((input.size() == 128 || input.size() == 256 || input.size() == 512)
        && ent > 7.0) {
        bool printable = false;
        for (unsigned char ch : input)
            if (ch >= 32 && ch <= 126) { printable = true; break; }
        if (!printable) {
            CipherCandidate c;
            size_t bits = input.size() * 8;
            c.cipher_name = bits == 1024 ? "rsa-1024" :
                            bits == 2048 ? "rsa-2048" : "rsa-4096";
            c.confidence = 0.75;
            c.decrypted = input;
            c.key = "try: ob-crypt rsa-decrypt -c <hex> -d <d> -n <n>";
            results.push_back(c);
        }
    }

    return results;
}

static void bifid_rows_from_keyword(const std::string &keyword, std::string rows[5]) {
    bool used[26] = {};
    used['J'-'A'] = true;
    std::string seq;
    for (char c : keyword) {
        if (c >= 'a' && c <= 'z') c = c-'a'+'A';
        if (c < 'A' || c > 'Z') continue;
        if (c == 'J') c = 'I';
        if (!used[c-'A']) { seq += c; used[c-'A'] = true; }
    }
    for (char c = 'A'; c <= 'Z'; c++)
        if (!used[c-'A']) seq += c;
    for (int i = 0; i < 5; i++)
        rows[i] = seq.substr(i * 5, 5);
}

static std::vector<CipherCandidate> pass_scytale(const std::string &input) {
    std::vector<CipherCandidate> results;
    static bool qg_ok = []() {
        try { (void)quadgram_score_per_letter("test"); return true; }
        catch (...) { return false; }
    }();
    std::string clean;
    for (unsigned char ch : input)
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
    if (clean.size() < 10) return results;
    int best_key = 2;
    double best_score = qg_ok ? -99999.0 : 999999.0;
    int max_sk = g_aggressive ? 40 : 20;
    for (int key = 2; key <= max_sk; key++) {
        std::string out;
        scytale_decrypt(input, out, key);
        std::string dc;
        for (unsigned char ch : out)
            if (std::isalpha(ch)) dc += (char)std::toupper(ch);
        if (dc.size() < 4) continue;
        if (qg_ok) {
            double qs = quadgram_score_per_letter(dc);
            if (qs > best_score) { best_score = qs; best_key = key; }
        } else {
            double s = score_english_combined(dc);
            if (s < best_score) { best_score = s; best_key = key; }
        }
    }
    std::string out;
    scytale_decrypt(input, out, best_key);
    double s = quadgram_chi_scaled(out);
    CipherCandidate c;
    c.cipher_name = "scytale";
    c.decrypted = out;
    c.key = std::to_string(best_key);
    c.confidence = normalize_confidence(s, "transposition");
    if (qg_ok) {
        if (best_score > -3.5) c.confidence = std::max(c.confidence, 0.85);
        else if (best_score > -5.0) c.confidence = std::max(c.confidence, 0.75);
        else if (best_score > -6.5) c.confidence = std::max(c.confidence, 0.65);
    }
    if (is_encoding_like(input)) {
        c.confidence = std::min(c.confidence, 0.50);
    }
    results.push_back(c);
    return results;
}

static std::vector<CipherCandidate> pass_bifid(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input) {
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
        else if (!std::isspace(ch)) return results;
    }
    if (clean.size() < 8) return results;
    double ioc = compute_ioc(clean);
    if (ioc < 0.020 || ioc > 0.085) return results;
    std::vector<const char *> all_bifid_keys = {
        "KEYWORD", "CRYPTO", "BIFID", "SECRET", "CIPHER", "KEY",
        "CODE", "TEST", "FLAG", "MESSAGE", "DECODE"
    };
    if (g_aggressive) {
        static const char *bifid_extra[] = {
            "PLANET","STAR","MOON","SUN","EARTH","WATER","FIRE","WIND",
            "ALPHA","BETA","DELTA","GAMMA","OMEGA","SIGMA","APPLE",
            "ORANGE","GRAPE","MELON","BERRY","PEACH"
        };
        for (auto *k : bifid_extra) all_bifid_keys.push_back(k);
    }
    for (auto *keyword : all_bifid_keys) {
        char grid[6][6]; int row_of[256] = {}, col_of[256] = {};
        std::string rows[5];
        bifid_rows_from_keyword(keyword, rows);
        build_bifid_grid(rows, grid, row_of, col_of);
        std::string out;
        bifid_decrypt(clean, out, grid, row_of, col_of);
        double score = score_english_combined(out);
        if (score >= 120.0) continue;
        CipherCandidate c;
        c.cipher_name = "bifid";
        c.decrypted = out;
        c.key = keyword;
        c.confidence = normalize_confidence(score, "substitution");
        if (score < 80.0 && c.confidence < 0.70)
            c.confidence = 0.70;
        results.push_back(c);
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.50);
    }
    return results;
}

static std::vector<CipherCandidate> pass_trifid(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input) {
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
        else if (!std::isspace(ch)) return results;
    }
    if (clean.size() < 12) return results;
    double ioc = compute_ioc(clean);
    if (ioc < 0.020 || ioc > 0.085) return results;
    static const char *common_keys[] = {
        "KEYWORD", "CRYPTO", "TRIFID", "SECRET", "CIPHER", "KEY",
        "CODE", "TEST", "ALPHABET", "XYZ", "MESSAGE",
        "PASSWORD", "CLEARTEXT", "ENCRYPT", "DECODE"
    };
    for (auto *key : common_keys) {
        for (int period = 3; period <= 7; period++) {
            std::string out;
            trifid(clean, out, key, period, false);
            if (out.empty()) continue;
            double score = score_english_combined(out);
            if (score >= 120.0) continue;
            CipherCandidate c;
            c.cipher_name = "trifid";
            c.decrypted = out;
            c.key = std::string(key) + " period=" + std::to_string(period);
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 80.0 && c.confidence < 0.70)
                c.confidence = 0.70;
            results.push_back(c);
        }
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.50);
    }
    return results;
}

static std::vector<CipherCandidate> pass_four_square(const std::string &input) {
    std::vector<CipherCandidate> results;
    std::string clean;
    for (unsigned char ch : input) {
        if (std::isalpha(ch)) clean += (char)std::toupper(ch);
        else if (!std::isspace(ch)) return results;
    }
    if (clean.size() < 8 || clean.size() % 2 != 0) return results;
    double ioc = compute_ioc(clean);
    if (ioc < 0.030 || ioc > 0.090) return results;
    std::vector<const char *> all_fs_keys = {
        "KEYWORD", "CRYPTO", "SQUARE", "SECRET", "CIPHER",
        "CODE", "TEST", "FLAG", "MESSAGE", "DECODE"
    };
    if (g_aggressive) {
        static const char *fs_extra[] = {
            "ALPHA", "BETA", "DELTA", "GAMMA", "OMEGA"
        };
        for (auto *k : fs_extra) all_fs_keys.push_back(k);
    }
    for (auto *k1 : all_fs_keys) {
        for (auto *k2 : all_fs_keys) {
            std::string out;
            four_square(clean, out, k1, k2, false);
            double score = score_english_combined(out);
            if (score >= 100.0) continue;
            CipherCandidate c;
            c.cipher_name = "four-square";
            c.decrypted = out;
            c.key = std::string(k1) + "," + k2;
            c.confidence = normalize_confidence(score, "substitution");
            if (score < 60.0 && c.confidence < 0.70)
                c.confidence = 0.70;
            results.push_back(c);
        }
    }
    if (is_encoding_like(input)) {
        for (auto &c : results) c.confidence = std::min(c.confidence, 0.50);
    }
    return results;
}

static void detect_cipher_internal(
    const std::string &input,
    int top_n,
    int depth,
    int &candidate_count,
    std::vector<CipherCandidate> &candidates,
    bool allow_branch = true,
    bool aggressive = false)
{
    if (candidate_count >= MAX_CANDIDATES) return;
    g_aggressive = aggressive;

    static const std::vector<DetectorPass> always_passes = {
        {"plaintext", pass_plaintext, true},
        {"ctf-flag", pass_ctf_flag, true},
        {"high-entropy", pass_high_entropy, true},
        {"hex", pass_hex, true},
        {"base64", pass_base64, true},
        {"base32", pass_base32, true},
        {"structural", [](const std::string &s) { return detect_structural_pass(s); }, true},
        {"morse", pass_morse, true},
        {"bacon", pass_bacon, true},
        {"base85", pass_base85, true},
        {"rot13", pass_rot13, true},
        {"rot47", pass_rot47, true},
        {"atbash", pass_atbash, true},
        {"binary", pass_binary, true},
        {"octal", pass_octal, true},
        {"large-base", pass_large_base, true},
        {"url", pass_urlcode, true},
        {"polybius", pass_polybius, true},
        {"braille", pass_braille, true},
        {"hash", pass_hash, true},
        {"base58", pass_base58, true},
        {"reverser", pass_reverser, true},
        {"rsa-fingerprint", pass_rsa_fingerprint, true},
    };

    static const std::vector<DetectorPass> cond_passes = {
        {"keyboard-shift", pass_keyboard_shift, false},
        {"caesar", pass_caesar, false},
        {"a1z26", pass_a1z26, false},
        {"railfence", pass_railfence, false},
        {"playfair", pass_playfair, false},
        {"xor", pass_xor, false},
        {"substitution", pass_substitution, false},
        {"vigenere", pass_vigenere, false},
        {"columnar", pass_columnar, false},
        {"digraph", pass_digraph_analysis, false},
        {"beaufort", pass_beaufort, false},
        {"autokey", pass_autokey, false},
        {"adfgvx", pass_adfgvx, false},
        {"keyword", pass_keyword, false},
        {"affine", pass_affine, false},
        {"hill",       pass_hill,       false},
        {"porta",      pass_porta,      false},
        {"gronsfeld",  pass_gronsfeld,  false},
        {"scytale",    pass_scytale,      false},
        {"bifid",      pass_bifid,        false},
        {"trifid",     pass_trifid,        false},
        {"four-square",pass_four_square,   false},
    };

    static const std::unordered_set<std::string> raw_encodings = {
        "hex","base64","base32","base58","base85","binary","octal",
        "large-base"
    };
    for (auto &pass : always_passes) {
        if (candidate_count >= MAX_CANDIDATES) break;
        auto results = pass.run(input);
        for (auto &c : results) {
            if (candidate_count >= MAX_CANDIDATES) break;
            if (!raw_encodings.count(pass.name) && !is_mostly_printable(c.decrypted)) continue;
            if (raw_encodings.count(pass.name) && !is_mostly_printable(c.decrypted))
                c.confidence = std::min(c.confidence, 0.15);
            candidates.push_back(c);
            candidate_count++;
        }
    }

    double best_conf = 0.0;
    for (auto &c : candidates)
        if (c.confidence > best_conf) best_conf = c.confidence;

    bool skip_expensive = (best_conf >= HIGH_CONF_THRESHOLD);
    for (auto &pass : cond_passes) {
        if (candidate_count >= MAX_CANDIDATES) break;
        if (skip_expensive && (pass.name == "substitution" || pass.name == "xor")) continue;
        auto results = pass.run(input);
        for (auto &c : results) {
            if (candidate_count >= MAX_CANDIDATES) break;
            if (!is_mostly_printable(c.decrypted)) continue;
            candidates.push_back(c);
            candidate_count++;
        }
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const CipherCandidate &a, const CipherCandidate &b) {
            return a.confidence > b.confidence;
        });

    int effective_top = std::min(top_n, (int)candidates.size());
    if (effective_top <= 0) effective_top = 3;
    if ((int)candidates.size() > effective_top)
        candidates.resize(effective_top);

    if (allow_branch && depth < MAX_DEPTH - 1 && !candidates.empty()) {
        CipherCandidate &best = candidates[0];
        if (best.decrypted != input) {
            double chi = score_english_combined(best.decrypted);
            if (chi > RECURSE_CHI_SQ && !best.decrypted.empty()) {
                if (BranchExplorer::should_branch(candidates, input)) {
                    BranchExplorer explorer(2, 3);
                    auto branch_results = explorer.explore(input, candidates, top_n);
                    for (size_t i = 0; i < branch_results.size() && i < candidates.size(); i++) {
                        auto &result = branch_results[i];
                        candidates[i].confidence = compute_branch_score(candidates[i], result.sub_candidates);
                        candidates[i].was_branched = true;
                        if (!result.sub_candidates.empty()
                            && result.sub_candidates[0].confidence > 0.70
                            && score_english_combined(result.sub_candidates[0].decrypted) < 30.0) {
                            if (candidate_count >= MAX_CANDIDATES) break;
                            CipherCandidate new_c;
                            new_c.cipher_name = candidates[i].cipher_name + "+" + result.sub_candidates[0].cipher_name;
                            new_c.decrypted = result.sub_candidates[0].decrypted;
                            new_c.confidence = candidates[i].confidence * 0.5 + result.sub_candidates[0].confidence * 0.5;
                            new_c.key = result.sub_candidates[0].key;
                            new_c.was_branched = true;
                            candidates.push_back(new_c);
                            candidate_count++;
                        }
                    }
                }
            }
        }
    }

    std::sort(candidates.begin(), candidates.end(),
        [](const CipherCandidate &a, const CipherCandidate &b) {
            return a.confidence > b.confidence;
        });

    effective_top = std::min(top_n, (int)candidates.size());
    if (effective_top <= 0) effective_top = 3;
    if ((int)candidates.size() > effective_top)
        candidates.resize(effective_top);
}

std::vector<CipherCandidate> detect_cipher(const std::string &input, int top_n, bool aggressive) {
    if (top_n <= 0) top_n = 3;
    if (input.empty()) return {};
    std::vector<CipherCandidate> candidates;
    int candidate_count = 0;
    detect_cipher_internal(input, top_n, 0, candidate_count, candidates, true, aggressive);
    return candidates;
}

std::vector<CipherCandidate> detect_cipher_no_branch(const std::string &input, int top_n, bool aggressive) {
    if (top_n <= 0) top_n = 3;
    if (input.empty()) return {};
    std::vector<CipherCandidate> candidates;
    int candidate_count = 0;
    detect_cipher_internal(input, top_n, 0, candidate_count, candidates, false, aggressive);
    return candidates;
}

std::vector<CipherCandidate> detect_base(const std::string &input, int top_n) {
    if (top_n <= 0) top_n = 3;
    if (input.empty()) return {};
    auto all = detect_cipher(input, 20);
    std::vector<CipherCandidate> results;
    static const char *base_names[] = {
        "hex", "base64", "base32", "base85", "base58",
        "binary", "octal", "large-base",
        "base2", "base8", "base10", "base16",
        "base32", "base36", "base62"
    };
    for (auto &c : all) {
        for (const char *b : base_names) {
            if (c.cipher_name == b) {
                results.push_back(c);
                break;
            }
            if (c.cipher_name.size() > 5 &&
                c.cipher_name.substr(0, 4) == "base" &&
                c.cipher_name.substr(4).find_first_not_of("0123456789") == std::string::npos) {
                results.push_back(c);
                break;
            }
        }
    }
    std::sort(results.begin(), results.end(),
        [](const CipherCandidate &a, const CipherCandidate &b) {
            return a.confidence > b.confidence;
        });
    if ((int)results.size() > top_n) results.resize(top_n);
    return results;
}

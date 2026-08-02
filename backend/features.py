from urllib.parse import urlparse
import re

def extract_features(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    features = {
        "url_length": len(url),
        "domain_length": len(domain),
        "path_length": len(path),

        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_underscores": url.count('_'),
        "num_slashes": url.count('/'),
        "num_question_marks": url.count('?'),
        "num_equal": url.count('='),
        "num_at": url.count('@'),
        "num_ampersand": url.count('&'),

        "num_digits": sum(c.isdigit() for c in url),
        "num_letters": sum(c.isalpha() for c in url),

        "has_https": int(url.startswith("https")),
        "has_ip": int(bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)))
    }

    return features
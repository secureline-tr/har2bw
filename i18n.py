"""Turkish/English UI and report strings. Unknown keys fall back to English, then the key."""

LANGUAGES = {'en': 'English', 'tr': 'Türkçe'}

MESSAGES = {
    'en': {
        'title': 'HAR2BW — Policy Review',
        'warning': 'Use authorized test traffic only. HARs may contain secrets. Policies are drafts; verify backend authorization.',
        'language': 'Language',
        'project': 'Project',
        'project_none': '(no project)',
        'project_new': 'New project name',
        'project_create': 'Create project',
        'save_history': 'Save reviewed bundle to project history',
        'saved_history': 'Saved as {version}',
        'history_title': 'Project history',
        'history_empty': 'No saved versions yet.',
        'filter_text': 'Filter candidates (path contains)',
        'filter_category': 'Category',
        'filter_all': 'All',
        'filter_selected_hidden': 'Hidden candidates keep their selection state.',
        'overlaps': 'Possible overlaps (review hints only)',
        'unobserved': 'Unobserved rule lines',
        'duplicates': 'Duplicate rule groups',
        'unknown_lines': 'Unrecognized lines',
        'prev_approval': 'Previous approval file (optional comparison)',
        'download_csv': 'Download CSV report',
        'download_pdf': 'Download PDF report',
        'report_sensitive': 'Reports may contain sensitive paths; store them like customer data.',
        'login': 'Password',
        'login_button': 'Sign in',
        'login_bad': 'Wrong password',
        'login_wait': 'Too many attempts; reload the page and wait.',
        'report_title': 'HAR2BW review report',
        'host': 'Target hostname',
        'har_files': 'HAR files',
        'numeric_ids': 'Generalize 1-9 digit numeric path segments (<int>); requires an explicit gate below',
        'clear': 'Clear review',
        'analyze': 'Analyze',
        'requests': 'Requests',
        'candidates': 'Candidates',
        'scope': 'Review scope: {host}',
        'dl_inventory': 'Download inventory (may contain sensitive paths)',
        'existing_conf': 'Existing HTTP configuration (offline comparison)',
        'dl_comparison': 'Download comparison',
        'gate_sensitive': 'I reviewed sensitive endpoints and backend authorization',
        'gate_dynamic': 'I reviewed generalized UUID paths',
        'gate_numeric': 'I reviewed generalized numeric ID paths',
        'gate_query': 'I accept unrestricted query strings for the selected observed query endpoints',
        'gate_redirect': 'I reviewed redirect-only candidates',
        'cidrs': 'Trusted internal CIDRs (optional, one per line)',
        'gate_real_ip': 'I verified trusted proxies and client IP spoofing protection for internal bypass',
        'generate': 'Generate draft',
        'dl_http': 'Global HTTP draft',
        'dl_server': 'Service SERVER_HTTP draft',
        'dl_bundle': 'Download review bundle',
        'review_asset': 'asset',
        'review_sensitive': 'sensitive',
        'col_status': 'status',
        'col_method': 'method',
        'col_path': 'path',
        'col_lines': 'lines',
        'col_broad': 'broad_line',
        'col_covered': 'covered_lines',
        'st_textual_match': 'textual_match',
        'st_review_missing_or_unsupported': 'review_missing_or_unsupported',
    },
    'tr': {
        'title': 'HAR2BW — Politika İncelemesi',
        'warning': 'Yalnızca yetkili test trafiği kullanın. HAR dosyaları gizli bilgi içerebilir. Politikalar taslaktır; arka uç yetkilendirmesini doğrulayın.',
        'language': 'Dil',
        'project': 'Proje',
        'project_none': '(proje yok)',
        'project_new': 'Yeni proje adı',
        'project_create': 'Proje oluştur',
        'save_history': 'İncelenen paketi proje geçmişine kaydet',
        'saved_history': '{version} olarak kaydedildi',
        'history_title': 'Proje geçmişi',
        'history_empty': 'Henüz kayıtlı sürüm yok.',
        'filter_text': 'Adayları filtrele (yol içerir)',
        'filter_category': 'Kategori',
        'filter_all': 'Tümü',
        'filter_selected_hidden': 'Gizlenen adaylar seçim durumunu korur.',
        'overlaps': 'Olası örtüşmeler (yalnızca inceleme ipucu)',
        'unobserved': 'Gözlenmeyen kural satırları',
        'duplicates': 'Yinelenen kural grupları',
        'unknown_lines': 'Tanınmayan satırlar',
        'prev_approval': 'Önceki onay dosyası (isteğe bağlı karşılaştırma)',
        'download_csv': 'CSV raporunu indir',
        'download_pdf': 'PDF raporunu indir',
        'report_sensitive': 'Raporlar hassas yollar içerebilir; müşteri verisi gibi saklayın.',
        'login': 'Parola',
        'login_button': 'Giriş yap',
        'login_bad': 'Yanlış parola',
        'login_wait': 'Çok fazla deneme; sayfayı yenileyip bekleyin.',
        'report_title': 'HAR2BW inceleme raporu',
        'host': 'Hedef ana makine adı',
        'har_files': 'HAR dosyaları',
        'numeric_ids': '1-9 haneli sayısal yol bölümlerini genelleştir (<int>); aşağıda açık onay gerekir',
        'clear': 'İncelemeyi temizle',
        'analyze': 'Analiz et',
        'requests': 'İstekler',
        'candidates': 'Adaylar',
        'scope': 'İnceleme kapsamı: {host}',
        'dl_inventory': 'Envanteri indir (hassas yollar içerebilir)',
        'existing_conf': 'Mevcut HTTP yapılandırması (çevrimdışı karşılaştırma)',
        'dl_comparison': 'Karşılaştırmayı indir',
        'gate_sensitive': 'Hassas uç noktaları ve arka uç yetkilendirmesini inceledim',
        'gate_dynamic': 'Genelleştirilmiş UUID yollarını inceledim',
        'gate_numeric': 'Genelleştirilmiş sayısal ID yollarını inceledim',
        'gate_query': 'Seçilen ve sorgu dizesi gözlenen uç noktalar için kısıtsız sorgu dizelerini kabul ediyorum',
        'gate_redirect': 'Yalnızca yönlendirme gözlenen adayları inceledim',
        'cidrs': 'Güvenilir iç CIDR blokları (isteğe bağlı, satır başına bir tane)',
        'gate_real_ip': 'İç ağ muafiyeti için güvenilir vekil sunucuları ve istemci IP sahteciliği korumasını doğruladım',
        'generate': 'Taslak oluştur',
        'dl_http': 'Global HTTP taslağı',
        'dl_server': 'Servis SERVER_HTTP taslağı',
        'dl_bundle': 'İnceleme paketini indir',
        'review_asset': 'varlık',
        'review_sensitive': 'hassas',
        'col_status': 'durum',
        'col_method': 'yöntem',
        'col_path': 'yol',
        'col_lines': 'satırlar',
        'col_broad': 'geniş_satır',
        'col_covered': 'kapsanan_satırlar',
        'st_textual_match': 'metinsel eşleşme',
        'st_review_missing_or_unsupported': 'eksik veya desteklenmiyor (incele)',
    },
}


def t(key, lang='en', **values):
    text = MESSAGES.get(lang, {}).get(key) or MESSAGES['en'].get(key) or key
    return text.format(**values) if values else text


# Display-only translations of messages produced by the analysis modules. The English
# originals stay untouched in reports (they are part of the approval-bound report hash).
EXACT_TR = {
    'Verify backend authorization, session scope and response content':
        'Arka uç yetkilendirmesini, oturum kapsamını ve yanıt içeriğini doğrulayın',
    'Potential state change; test using non-production records':
        'Olası durum değişikliği; üretim dışı kayıtlarla test edin',
    'UUID pattern covers other IDs; verify object-level authorization':
        'UUID deseni başka kimlikleri de kapsar; nesne düzeyinde yetkilendirmeyi doğrulayın',
    'Numeric pattern covers other IDs; verify object-level authorization':
        'Sayısal desen başka kimlikleri de kapsar; nesne düzeyinde yetkilendirmeyi doğrulayın',
    'Query values omitted; generated URI rule does not restrict query strings':
        'Sorgu değerleri atlandı; üretilen URI kuralı sorgu dizelerini kısıtlamaz',
    'High-risk application operation or sensitive data; manual review required':
        'Yüksek riskli uygulama işlemi veya hassas veri; elle inceleme gerekir',
    'Unsafe or opaque path; no rule can be generated':
        'Güvensiz veya anlaşılamayan yol; kural üretilemez',
    'Combined upload exceeds 128 MiB': 'Toplam yükleme 128 MiB sınırını aşıyor',
    'Configuration exceeds 2 MiB': 'Yapılandırma 2 MiB sınırını aşıyor',
    'Approval file exceeds 1 MiB': 'Onay dosyası 1 MiB sınırını aşıyor',
    'Previous approval belongs to another host': 'Önceki onay başka bir ana makineye ait',
    'Invalid HAR structure': 'Geçersiz HAR yapısı',
    'At least one HAR is required': 'En az bir HAR dosyası gerekir',
    'Combined HAR input exceeds 128 MiB': 'Toplam HAR girdisi 128 MiB sınırını aşıyor',
    'HAR exceeds 128 MiB limit': 'HAR dosyası 128 MiB sınırını aşıyor',
    'No approved candidates; no policy produced': 'Onaylı aday yok; politika üretilmedi',
    'Review changed: analyze and approve again': 'İnceleme değişti: yeniden analiz edip onaylayın',
    'Catch-all internal network is forbidden': 'Tüm ağları kapsayan iç ağ yasaktır',
    'Internal bypass requires explicit confirmation of trusted real-IP configuration':
        'İç ağ muafiyeti, güvenilir gerçek-IP yapılandırmasının açıkça onaylanmasını gerektirir',
    'Unknown candidate ID: regenerate the review file': 'Bilinmeyen aday kimliği: inceleme dosyasını yeniden oluşturun',
    'Invalid hostname (use lowercase DNS name, no scheme or port)':
        'Geçersiz ana makine adı (küçük harfli DNS adı kullanın, şema veya port olmadan)',
    'Invalid DNS hostname': 'Geçersiz DNS ana makine adı',
    'Textual matches do not prove effective access. Unobserved rules are not necessarily redundant. '
    'Overlaps are textual hints only. Never auto-remove.':
        'Metinsel eşleşmeler etkin erişimi kanıtlamaz. Gözlenmeyen kurallar mutlaka gereksiz değildir. '
        'Örtüşmeler yalnızca metinsel ipucudur. Asla otomatik silmeyin.',
}
PREFIX_TR = {
    'Candidate has no observed 2xx/redirect or unsupported path: ': 'Adayda gözlenen 2xx/yönlendirme yok veya yol desteklenmiyor: ',
    'Redirect-only candidate requires --allow-redirect-only: ': 'Yalnızca yönlendirme gözlenen aday için ilgili onay kutusu gerekir: ',
    'Sensitive candidate requires --allow-sensitive: ': 'Hassas aday için ilgili onay kutusu gerekir: ',
    'Dynamic candidate requires --allow-dynamic: ': 'UUID desenli aday için ilgili onay kutusu gerekir: ',
    'Numeric candidate requires --allow-numeric: ': 'Sayısal desenli aday için ilgili onay kutusu gerekir: ',
    'Unrestricted query requires --allow-unrestricted-query: ': 'Kısıtsız sorgu için ilgili onay kutusu gerekir: ',
}


def tx(text, lang='en'):
    """Translate a known analysis-module message for display; unknown text is returned unchanged."""
    if lang != 'tr':
        return text
    if text in EXACT_TR:
        return EXACT_TR[text]
    for prefix, replacement in PREFIX_TR.items():
        if text.startswith(prefix):
            return replacement + text[len(prefix):]
    return text

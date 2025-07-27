# Nettacker

Nettacker هي أداة فحص الشبكات مستوحاة من OWASP Nettacker. تم تطويرها لمساعدة المختبرين والمدققين في عمليات تقييم أمان الشبكات.

## المميزات

- فحص المنافذ المفتوحة
- كشف الثغرات الأمنية
- تحليل الخدمات
- فحص تطبيقات الويب باستخدام Wapiti
- اكتشاف المسارات المخفية
- فحص متقدم للمسارات باستخدام dirsearch (قوة مدمرة في اكتشاف المسارات المخفية)
- فحص شامل للمسارات باستخدام Gobuster (قوة مدمرة جداً في اكتشاف المسارات والملفات المخفية)
- إمكانية حفظ النتائج
- واجهة سطر أوامر سهلة الاستخدام

## المتطلبات

- Python 3.x
- المكتبات المطلوبة (يمكن تثبيتها باستخدام `pip install -r requirements.txt`)

## التثبيت

```bash
git clone https://github.com/SayerLinux/Nettacker.git
cd Nettacker
pip install -r requirements.txt
python3 nettacker.py -h
```

## الاستخدام

```bash
# فحص الثغرات التقليدي
python3 nettacker.py -H target.com -p 80,443 -m vuln -o results.txt

# فحص باستخدام Wapiti
python3 nettacker.py -H target.com -p 80,443 -m wapiti -o results.txt --wapiti-timeout 600

# فحص متقدم للمسارات باستخدام dirsearch (قوة مدمرة)
python3 nettacker.py -H target.com -p 80,443 -m dirsearch -o results.txt --dirsearch-extensions php,asp,html,txt,bak

# فحص متقدم للمسارات مع تحديد عدد مسارات الفحص المتزامنة
python3 nettacker.py -H target.com -p 80,443 -m dirsearch --dirsearch-threads 20 --dirsearch-timeout 60

# فحص شامل للمسارات باستخدام Gobuster (قوة مدمرة جداً)
python3 nettacker.py -H target.com -p 80,443 -m gobuster -o results.txt --gobuster-extensions php,asp,html,txt,bak,config,old,zip

# فحص شامل للمسارات باستخدام Gobuster مع تحديد عدد مسارات الفحص المتزامنة وقائمة كلمات مخصصة
python3 nettacker.py -H target.com -p 80,443 -m gobuster --gobuster-threads 30 --gobuster-timeout 60 --gobuster-wordlist /path/to/wordlist.txt

# فحص شامل (يتضمن فحص المنافذ، الخدمات، المسارات، الثغرات، Wapiti، dirsearch، وGobuster)
python3 nettacker.py -H target.com -p 80,443 -m all -o results.txt -v --dirsearch-extensions php,asp,html --gobuster-extensions php,txt,bak,config --wapiti-timeout 600
```

### الخيارات المتاحة

- `-H, --host`: عنوان الهدف المراد فحصه
- `-p, --ports`: المنافذ المراد فحصها (مفصولة بفواصل)
- `-m, --method`: طريقة الفحص (vuln, port, service, dir, wapiti, dirsearch, gobuster, all)
- `-o, --output`: حفظ النتائج في ملف
- `-v, --verbose`: تفعيل وضع التفاصيل الكاملة
- `-t, --timeout`: مهلة الاتصال بالثواني (الافتراضي: 3)
- `--threads`: عدد مسارات الفحص المتزامنة (الافتراضي: 10)
- `--wapiti-timeout`: مهلة فحص Wapiti بالثواني (الافتراضي: 300)
- `--dirsearch-wordlist`: مسار ملف قائمة الكلمات لفحص dirsearch
- `--dirsearch-extensions`: امتدادات الملفات للبحث عنها في فحص dirsearch (مثال: php,asp,html)
- `--dirsearch-threads`: عدد مسارات الفحص المتزامنة لـ dirsearch (الافتراضي: 10)
- `--dirsearch-timeout`: مهلة فحص dirsearch بالثواني (الافتراضي: 30)
- `--gobuster-wordlist`: مسار ملف قائمة الكلمات لفحص Gobuster
- `--gobuster-extensions`: امتدادات الملفات للبحث عنها في فحص Gobuster (مثال: php,asp,html,txt,bak,config)
- `--gobuster-threads`: عدد مسارات الفحص المتزامنة لـ Gobuster (الافتراضي: 20)
- `--gobuster-timeout`: مهلة فحص Gobuster بالثواني (الافتراضي: 30)

## المطور

- **الاسم**: SayerLinux
- **البريد الإلكتروني**: SaudiSayer@gmail.com

## الترخيص

هذا المشروع مرخص تحت رخصة MIT.
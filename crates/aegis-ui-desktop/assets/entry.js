'use strict';
(() => {
// core.js
'use strict';
/* Aegis 0.2.5 prototype: shared helpers. No framework; screens are plain
   functions that return elements. Strings come from i18n.rs through I18N. */

// ── DOM ──────────────────────────────────────────────────
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'indeterminate', 'muted', 'playsInline', 'tabIndex']);

function h(sel, props, ...kids) {
  let tag = 'div', id = '', cls = [];
  sel.replace(/([.#]?)([\w-]+)/g, (_, p, n) => { if (!p) tag = n; else if (p === '.') cls.push(n); else id = n; return ''; });
  const el = document.createElement(tag);
  if (id) el.id = id;
  if (cls.length) el.className = cls.join(' ');
  if (props != null && (typeof props !== 'object' || props instanceof Node || Array.isArray(props))) { kids.unshift(props); props = null; }
  for (const k in props) {
    const v = props[k];
    if (v == null || v === false) continue;
    if (k === 'class') el.className = (el.className + ' ' + v).trim();
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'html') el.innerHTML = v;
    else if (k === 'text') el.textContent = v;
    else if (PROPS.has(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  add(el, kids);
  return el;
}
function add(el, kids) {
  for (const k of kids.flat(Infinity)) if (k != null && k !== false) el.append(k instanceof Node ? k : String(k));
  return el;
}
const tpl = document.createElement('template');
function frag(html) { tpl.innerHTML = html.trim(); return tpl.content.firstElementChild.cloneNode(true); }
function ico(name, cls = '') { return frag(`<svg class="i ${cls}" aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`); }
const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const clamp = (v, a, b) => Math.min(b, Math.max(a, v));
const sleep = ms => new Promise(r => setTimeout(r, ms));
const raf = () => new Promise(r => requestAnimationFrame(r));
const uid = (() => { let n = 0; return p => (p || 'u') + (++n).toString(36); })();

// ── i18n ─────────────────────────────────────────────────
// I18N is { key: [en, ru] }: real strings from i18n.rs and look_text.rs, plus
// the d.* keys of design-strings.json that the brief asks for and i18n.rs lacks.
const I18N = {"auth.tagline":["No phone number, no email, no real name. A username and a password are enough.","Без номера телефона, почты и настоящего имени. Достаточно ника и пароля."],"auth.eyebrow":["PRIVATE BY DEFAULT","ПРИВАТНО ПО УМОЛЧАНИЮ"],"auth.chip1":["end-to-end encrypted","сквозное шифрование"],"auth.chip2":["no phone, no email","без телефона и почты"],"auth.chip3":["open source","открытый код"],"auth.foot":["Your boundaries. Your keys.","Ваши границы. Ваши ключи."],"auth.headline":["Everyone has a right to a private space.","У каждого есть право на личное пространство."],"auth.pwnote":["The password cannot be recovered. The server never receives it.","Пароль не восстанавливается. Сервер его никогда не получает."],"chat.hint":["End-to-end encrypted. The server sees only the queue and the time.","Сквозное шифрование. Сервер видит только очередь и время."],"contact.key_verified":["key verified","ключ проверен"],"ttl.short":["disappearing","исчезают"],"status.online":["Connected","Подключено"],"status.offline":["No connection","Нет соединения"],"status.connecting":["Connecting","Подключение"],"auth.tab_unlock":["Unlock","Войти"],"auth.tab_create":["Create","Создать"],"auth.tab_import":["Import","Импорт"],"auth.unlock":["Unlock","Войти"],"auth.create":["Create account","Создать аккаунт"],"auth.import":["Import","Импортировать"],"auth.import_note":["Enter the full path of a vault file exported from Aegis. It is decrypted first and only then copied into the data folder.","Укажите полный путь к файлу, экспортированному из Aegis. Сначала он расшифровывается и только потом копируется в папку данных."],"f.username":["Username","Ник"],"f.username_new":["Username (a-z, 0-9, _)","Ник (a-z, 0-9, _)"],"f.display":["Display name","Отображаемое имя"],"f.password":["Password","Пароль"],"f.password_new":["Password (10+ characters)","Пароль (от 10 символов)"],"f.confirm":["Repeat password","Повторите пароль"],"f.vault_path":["Vault file path","Путь к файлу"],"f.contact_username":["Username","Ник"],"f.group_title":["Group name","Название группы"],"f.endpoint":["Server address","Адрес сервера"],"f.socks5":["SOCKS5 proxy (host:port, optional)","SOCKS5-прокси (host:port, необязательно)"],"f.idle":["Lock after idle minutes (0 = never)","Блокировать после простоя, минут (0 — никогда)"],"f.export_path":["Full path for the exported file","Полный путь для файла экспорта"],"f.confirm_name":["Type your username to confirm","Введите свой ник для подтверждения"],"nav.settings":["Settings","Настройки"],"nav.lock":["Lock","Заблокировать"],"nav.new_chat":["New chat","Новый чат"],"nav.new_group":["New group","Новая группа"],"list.empty":["No chats yet. Start one with a username.","Чатов пока нет. Начните с ника собеседника."],"list.filter":["Filter chats","Фильтр чатов"],"main.welcome_title":["Aegis","Aegis"],"main.pick":["Select a chat or start a new one.","Выберите чат или начните новый."],"main.e2ee":["Messages are end-to-end encrypted. The server sees which queue receives a message and when, not its contents.","Сообщения шифруются сквозным шифрованием. Сервер видит, в какую очередь и когда пришло сообщение, но не его содержимое."],"chat.placeholder":["Message","Сообщение"],"chat.send":["Send","Отправить"],"chat.empty":["No messages yet.","Сообщений пока нет."],"chat.ttl_on":["Disappearing messages are on. New messages are deleted on both devices when the timer ends, counted from when each device got them.","Исчезающие сообщения включены. Новые сообщения удаляются на обоих устройствах по истечении таймера, который отсчитывается с момента получения."],"msg.sending":["sending...","отправка..."],"msg.failed":["not sent","не отправлено"],"msg.retry":["Retry","Повторить"],"ttl.label":["Disappearing messages","Исчезающие сообщения"],"ttl.off":["Off","Выкл"],"ttl.30s":["30 seconds","30 секунд"],"ttl.5m":["5 minutes","5 минут"],"ttl.1h":["1 hour","1 час"],"ttl.1d":["1 day","1 день"],"ttl.7d":["1 week","1 неделя"],"ttl.you":["You","Вы"],"warn.key_changed":["The keys of","Ключи контакта"],"warn.compare":["have changed. Messages signed with the new keys are not shown until you accept them. Compare the safety number with your contact first.","изменились. Сообщения с новыми ключами не показываются, пока вы их не примете. Сначала сверьте номер безопасности с собеседником."],"warn.group_only":["differ from the pinned ones in a group message. The message was dropped. Keys can only be accepted from a direct message.","в групповом сообщении отличаются от сохранённых. Сообщение отброшено. Принять новые ключи можно только из личного сообщения."],"warn.view":["Safety number","Номер безопасности"],"warn.accept":["Accept new key","Принять новый ключ"],"warn.dismiss":["Dismiss","Скрыть"],"contact.title":["Contact","Контакт"],"contact.verified":["verified","проверен"],"contact.unverified":["not verified","не проверен"],"contact.safety":["Safety number","Номер безопасности"],"contact.safety_note":["Compare these numbers with your contact over another channel. If they match, nobody replaced the keys between you.","Сверьте эти числа с собеседником по другому каналу. Если они совпали, ключи по дороге никто не подменил."],"contact.mark_verified":["Mark as verified","Отметить как проверенный"],"contact.delete":["Delete chat and contact","Удалить чат и контакт"],"newchat.note":["Enter the exact username of the person. Users cannot be searched. The server returns the public keys registered under that name, and they are pinned on first use.","Введите точный ник человека. Поиска пользователей нет. Сервер возвращает публичные ключи, зарегистрированные под этим ником, и они запоминаются при первом использовании."],"newchat.add":["Start chat","Начать чат"],"inv.title":["Invite link","Ссылка-приглашение"],"inv.note":["A link works once and for 7 days. Whoever opens it gets your keys directly, without a directory lookup. Share it only with the person you mean.","Ссылка срабатывает один раз и действует 7 дней. Открывший её получает ваши ключи напрямую, без запроса к каталогу. Передавайте её только тому, кому она предназначена."],"inv.create":["Create invite","Создать приглашение"],"inv.another":["Create another","Создать ещё"],"inv.copy":["Copy","Копировать"],"inv.open_title":["Open an invite","Открыть приглашение"],"inv.open_note":["Paste an aegis://invite/ link someone gave you.","Вставьте ссылку aegis://invite/, которую вам дали."],"inv.open":["Open","Открыть"],"f.invite_link":["Invite link","Ссылка-приглашение"],"busy.invite":["Talking to the server...","Связь с сервером..."],"err.invite_limit":["Too many open invites. Wait until some are used or expire.","Слишком много открытых приглашений. Дождитесь, пока часть будет использована или истечёт."],"err.invite_link":["This is not an invite link.","Это не ссылка-приглашение."],"err.invite_gone":["This invite was already used, has expired or does not exist.","Приглашение уже использовано, истекло или не существует."],"err.invite_conflict":["A contact with this name or these keys already exists with other keys. The invite was not applied.","Контакт с этим ником или этими ключами уже есть, но с другими ключами. Приглашение не применено."],"newgroup.note":["Up to 100 members including you. Only existing contacts can be added. Every member receives the group key in a direct message.","До 100 участников включая вас. Добавить можно только существующих контактов. Каждый участник получает ключ группы в личном сообщении."],"newgroup.members":["Members","Участники"],"newgroup.no_contacts":["Add contacts first.","Сначала добавьте контакты."],"newgroup.create":["Create group","Создать группу"],"group.info":["Group","Группа"],"group.members_n":["members","участников"],"group.you":["you","вы"],"group.creator":["creator","создатель"],"group.resend":["Resend invite","Отправить приглашение снова"],"group.leave":["Leave group","Покинуть группу"],"group.leave_note":["Leaving deletes the group from this device only. The other members keep the group key and can still read what they receive.","Выход удаляет группу только на этом устройстве. У остальных участников ключ группы остаётся, и они продолжают читать свои сообщения."],"dlg.delete_chat":["Delete chat","Удалить чат"],"dlg.delete_chat_text":["This removes the chat and the pinned keys of","Будут удалены чат и сохранённые ключи контакта"],"dlg.delete_account_text":["This deletes the vault file on this device. Without an exported copy the account cannot be restored. Type","Будет удалён файл хранилища на этом устройстве. Без экспортированной копии аккаунт не восстановить. Введите"],"common.back":["Back","Назад"],"common.cancel":["Cancel","Отмена"],"common.close":["Close","Закрыть"],"common.save":["Save","Сохранить"],"set.profile":["Profile","Профиль"],"set.connection":["Connection and lock","Соединение и блокировка"],"set.conn_note":["The default address is behind Cloudflare. TLS ends there, so Cloudflare can see your IP address and when you connect, but not message contents. A SOCKS5 proxy hides your address from the server operator and Cloudflare. Names are resolved through the proxy.","Адрес по умолчанию стоит за Cloudflare. TLS заканчивается там, поэтому Cloudflare видит ваш IP-адрес и время подключений, но не содержимое сообщений. SOCKS5-прокси скрывает ваш адрес от оператора сервера и Cloudflare. Имена разрешаются через прокси."],"set.flash":["Flash the taskbar on new messages (no message text is shown)","Мигать на панели задач при новых сообщениях (текст не показывается)"],"set.test":["Test connection","Проверить соединение"],"set.language":["Language","Язык"],"set.lang_note":["Takes effect immediately.","Применяется сразу."],"set.backup":["Backup","Резервная копия"],"set.backup_note":["Export copies the encrypted vault file to the path you give. It is protected by your password. Existing files are not overwritten.","Экспорт копирует зашифрованный файл хранилища по указанному пути. Он защищён вашим паролем. Существующие файлы не перезаписываются."],"set.export":["Export vault","Экспортировать"],"set.danger":["Delete account data","Удаление данных аккаунта"],"set.delete_note":["Deletes the vault file on this device only. The name stays registered on the server and cannot be reused.","Удаляет только файл хранилища на этом устройстве. Ник остаётся занят на сервере и не может быть использован снова."],"set.delete":["Delete account data on this device","Удалить данные аккаунта на этом устройстве"],"set.about":["About","О программе"],"set.about_text":["Aegis is an experimental end-to-end encrypted messenger. The protocol and the source code are public.","Aegis — экспериментальный мессенджер со сквозным шифрованием. Протокол и исходный код открыты."],"set.about_font":["Interface fonts: Geist and Geist Mono, SIL Open Font License 1.1.","Шрифты интерфейса: Geist и Geist Mono, лицензия SIL Open Font License 1.1."],"conn.running":["Testing...","Проверка..."],"conn.ok":["The server answered.","Сервер ответил."],"busy.create":["Creating account: generating keys and solving the registration puzzle...","Создание аккаунта: генерация ключей и решение задачи регистрации..."],"busy.unlock":["Unlocking...","Вход..."],"busy.lookup":["Looking up the user...","Поиск пользователя..."],"busy.group":["Creating group and sending invites...","Создание группы и отправка приглашений..."],"busy.profile":["Saving profile...","Сохранение профиля..."],"ok.saved":["Saved.","Сохранено."],"ok.exported":["Exported to","Экспортировано в"],"ok.deleted":["Account data deleted from this device.","Данные аккаунта удалены с этого устройства."],"ok.invite_sent":["Invite sent to","Приглашение отправлено:"],"err.generic":["Something went wrong.","Что-то пошло не так."],"err.taken":["This username is already taken.","Этот ник уже занят."],"err.queue_full":["The server refused the request: rate limit or full queue. Try again later.","Сервер отклонил запрос: лимит или переполненная очередь. Повторите позже."],"err.rejected":["The server rejected the request.","Сервер отклонил запрос."],"err.network":["Could not reach the server.","Не удалось связаться с сервером."],"err.password":["Wrong password or damaged vault file.","Неверный пароль или повреждённый файл."],"err.username":["Invalid username.","Недопустимый ник."],"err.endpoint":["Invalid server address.","Недопустимый адрес сервера."],"err.too_long":["The message is too long.","Сообщение слишком длинное."],"err.confirm":["The passwords do not match.","Пароли не совпадают."],"err.confirm_name":["The username does not match.","Ник не совпадает."],"err.password_short":["The password must have at least 10 characters.","Пароль должен содержать не меньше 10 символов."],"err.display":["Invalid display name (1 to 64 characters).","Недопустимое имя (от 1 до 64 символов)."],"err.exists":["An account with this name already exists on this device.","Аккаунт с таким ником уже есть на этом устройстве."],"err.file_exists":["The file already exists. Choose another path.","Файл уже существует. Выберите другой путь."],"err.path":["Enter a full path in an existing folder.","Укажите полный путь в существующей папке."],"err.no_account":["No account with this username on this device.","На этом устройстве нет аккаунта с таким ником."],"err.vault_format":["The file is not a valid Aegis vault.","Файл не является хранилищем Aegis."],"err.disk":["Could not read or write the file.","Не удалось прочитать или записать файл."],"err.locked":["Not unlocked.","Хранилище заблокировано."],"err.self":["That is your own username.","Это ваш собственный ник."],"err.not_found":["No user with this username on the server.","Пользователь с таким ником на сервере не найден."],"err.empty":["The message is empty.","Сообщение пустое."],"err.no_contact":["Unknown contact.","Неизвестный контакт."],"err.no_group":["Unknown group.","Неизвестная группа."],"err.group_title":["Enter a group name.","Введите название группы."],"err.group_members":["Select at least one member.","Выберите хотя бы одного участника."],"err.group_big":["A group can have at most 100 members including you.","В группе не больше 100 участников, включая вас."],"err.invite_failed":["The group was created, but these invites were not delivered. Resend them from the group page:","Группа создана, но приглашения не доставлены. Отправьте их снова на странице группы:"],"err.socks":["The proxy must look like host:port.","Прокси должен иметь вид host:port."],"tab.all":["All","Все"],"tab.groups":["Groups","Группы"],"tab.channels":["Channels","Каналы"],"drawer.account":["Settings","Настройки"],"nav.new_channel":["New channel","Новый канал"],"nav.contacts":["Contacts","Контакты"],"list.you":["You:","Вы:"],"list.lookup":["Search the server for","Искать на сервере:"],"media.photo":["Photo","Фото"],"media.video":["Video","Видео"],"chan.official":["Official channel","Официальный канал"],"chan.channel":["Channel","Канал"],"chan.subs_n":["subscribers","подписчиков"],"chan.official_tag":["official","официальный"],"chan.manage":["Channel","Канал"],"chan.invite":["Invite selected","Пригласить выбранных"],"chan.delete":["Delete channel","Удалить канал"],"chan.leave":["Leave channel","Покинуть канал"],"chan.leave_note":["The channel is removed from this device only. Posts you already received stay with the other subscribers.","Канал будет удалён только на этом устройстве. У остальных подписчиков полученные записи останутся."],"chan.key_changed":["The key of the channel owner differs from the saved one. New posts are not shown.","Ключ владельца канала отличается от сохранённого. Новые записи не показываются."],"menu.info":["Info","Информация"],"menu.pin":["Pin","Закрепить"],"menu.unpin":["Unpin","Открепить"],"menu.mute":["Mute","Выключить уведомления"],"menu.unmute":["Unmute","Включить уведомления"],"menu.clear":["Clear history","Очистить историю"],"menu.more":["More","Ещё"],"chat.search":["Search in chat","Поиск в чате"],"chat.attach":["Attach a photo or video","Прикрепить фото или видео"],"info.media":["Shared media","Медиа"],"newchannel.note":["Anyone you invite can read what you post. Subscribers cannot write. Up to 200 subscribers.","Приглашённые читают ваши записи, но писать не могут. До 200 подписчиков."],"newchannel.create":["Create channel","Создать канал"],"f.channel_title":["Channel name","Название канала"],"f.about":["About (up to 140 characters)","О себе (до 140 символов)"],"f.particles":["Particles","Частицы"],"contacts.chat":["Chat","Чат"],"acct.profile":["Account","Аккаунт"],"acct.privacy":["Security and privacy","Безопасность и приватность"],"acct.notifications":["Notifications","Уведомления"],"acct.appearance":["Appearance","Оформление"],"acct.connection":["Network and Tor","Сеть и Tor"],"acct.data":["Backup and deletion","Копия и удаление"],"pfx.none":["None","Нет"],"pfx.dust":["Dust","Пыль"],"pfx.snow":["Snow","Снег"],"pfx.embers":["Embers","Угли"],"pfx.orbit":["Orbit","Орбита"],"pfx.rain":["Rain","Дождь"],"profile.note":["Your name and about line are sent to your contacts.","Имя и строка о себе отправляются вашим контактам."],"priv.lock":["App lock","Блокировка приложения"],"priv.lock_min":["Also lock when the window is minimized","Блокировать и при сворачивании окна"],"priv.lock_note":["With the lock on, the app locks after the idle time above (0 turns that off) and, if chosen, when minimized. Opening the app always needs your password or PIN, because they unlock the encrypted vault.","Когда блокировка включена, приложение блокируется после указанного времени бездействия (0 отключает это) и, если выбрано, при сворачивании. Для запуска всегда нужен пароль или PIN-код: ими открывается зашифрованное хранилище."],"priv.protect":["Hide the window from screen capture","Скрывать окно от захвата экрана"],"priv.lookup":["Profile lookup","Поиск профиля"],"priv.hidden":["Hide profile","Скрыть профиль"],"priv.hidden_note":["Looking up your username then answers \"not found\". New contacts can reach you only through an invite link. Existing contacts are not affected.","Поиск по вашему нику будет отвечать «не найден». Новые контакты смогут найти вас только по ссылке-приглашению. Существующие контакты это не затронет."],"priv.protect_note":["Screenshots and screen sharing show a blank window.","На снимках и в трансляции экрана окно будет пустым."],"priv.pin":["PIN","PIN-код"],"priv.set_pin":["Set PIN","Задать PIN"],"priv.set_duress":["Set duress PIN","Задать PIN принуждения"],"priv.pin_note":["With a PIN you unlock with 4 or 6 digits instead of the password. The server counts the attempts and gives up the secret after five wrong ones. A duress PIN erases this account from the device and then shows the usual wrong-PIN message.","С PIN-кодом вы входите четырьмя или шестью цифрами вместо пароля. Сервер считает попытки и после пяти неверных перестаёт выдавать секрет. PIN принуждения стирает этот аккаунт с устройства и показывает обычное сообщение о неверном PIN."],"priv.pin_on":["A PIN is set.","PIN-код задан."],"priv.duress_on":["A duress PIN is set.","PIN принуждения задан."],"priv.remove_pin":["Remove PIN","Убрать PIN"],"priv.clear_duress":["Remove duress PIN","Убрать PIN принуждения"],"f.pin":["PIN (4 or 6 digits)","PIN (4 или 6 цифр)"],"f.pin_confirm":["Repeat the PIN","Повторите PIN"],"f.pin_current":["Current PIN","Текущий PIN"],"f.duress":["Duress PIN","PIN принуждения"],"f.secret":["Password or PIN","Пароль или PIN"],"busy.pin":["Talking to the server...","Связь с сервером..."],"ok.pin_set":["PIN set.","PIN задан."],"ok.pin_removed":["PIN removed.","PIN убран."],"ok.duress_set":["Duress PIN set.","PIN принуждения задан."],"ok.duress_cleared":["Duress PIN removed.","PIN принуждения убран."],"err.pin_format":["A PIN is 4 or 6 digits.","PIN состоит из 4 или 6 цифр."],"err.pin_mismatch":["The PINs do not match.","PIN-коды не совпадают."],"err.pin_exists":["A PIN is already set.","PIN уже задан."],"err.pin_none":["No PIN is set.","PIN не задан."],"err.pin_wrong":["Wrong PIN. Tries left","Неверный PIN. Осталось попыток"],"err.pin_throttled":["Try again in a moment.","Попробуйте через минуту."],"err.pin_gone":["This PIN no longer works. Enter your password.","Этот PIN больше не действует. Введите пароль."],"err.duress_same":["The duress PIN must differ from your PIN.","PIN принуждения должен отличаться от вашего PIN."],"notify.on":["Notify about new messages","Уведомлять о новых сообщениях"],"notify.name":["Show the sender and text in notifications","Показывать отправителя и текст в уведомлениях"],"notify.note":["When off, a notification says only New message, with no sender and no text. Nothing arrives while the app is locked. Muted chats stay silent.","Если выключено, уведомление говорит только «Новое сообщение», без отправителя и текста. Пока приложение заблокировано, уведомлений нет. Чаты без звука молчат."],"notify.new":["New message","Новое сообщение"],"conn.cover":["Cover traffic","Маскирующий трафик"],"conn.cover_note":["Cover traffic hides when you are really talking. It stops while the app is locked or minimized.","Маскирующий трафик скрывает, когда вы действительно общаетесь. Он останавливается, пока приложение заблокировано или свёрнуто."],"conn.cover_off":["Off","Выключен"],"conn.cover_std":["Standard","Обычный"],"conn.cover_high":["High","Усиленный"],"conn.tor":["Connect through Tor","Подключаться через Tor"],"conn.tor_note":["Tor is built into the app. With it on, the app reaches the server through its onion address and sends nothing until Tor is connected. The proxy field is ignored; turn Tor off to use it.","Tor встроен в приложение. Когда он включён, приложение подключается к серверу через onion-адрес и ничего не отправляет, пока Tor не подключился. Поле прокси при этом не используется; выключите Tor, чтобы им пользоваться."],"conn.tor_off":["Tor is off: the server sees your address.","Tor выключен: сервер видит ваш адрес."],"conn.tor_start":["Tor is connecting","Tor подключается"],"conn.tor_ready":["Tor is connected.","Tor подключён."],"conn.tor_failed":["Tor could not connect, retrying.","Tor не удалось подключить, повторяю попытку."],"conn.tor_bridge":["Bridges:","Мосты:"],"conn.bridges":["Tor bridges","Мосты Tor"],"conn.bridges_off":["Off","Выключены"],"conn.bridges_snowflake":["Snowflake (built-in)","Snowflake (встроенные)"],"conn.bridges_obfs4":["obfs4 (built-in)","obfs4 (встроенные)"],"conn.bridges_custom":["WebTunnel or own bridges","WebTunnel или свои мосты"],"f.bridge_lines":["Bridge lines, one per line","Строки мостов, по одной на строку"],"conn.bridges_note":["Use bridges where Tor is blocked. Snowflake works in most places; if it does not, try obfs4. For WebTunnel or private bridges get lines from bridges.torproject.org or @GetBridgesBot in Telegram and paste them here.","Мосты нужны там, где Tor заблокирован. Snowflake работает почти везде; если нет, попробуйте obfs4. Для WebTunnel или частных мостов получите строки на bridges.torproject.org или у @GetBridgesBot в Telegram и вставьте их сюда."],"err.bridge_line":["Not a bridge line, line","Это не строка моста, строка"],"err.bridges_empty":["Paste at least one bridge line.","Вставьте хотя бы одну строку моста."],"err.bridges_many":["Too many bridge lines.","Слишком много строк мостов."],"err.clearnet_tor":["This address is the clearnet entry behind Cloudflare. With Tor on the app uses the onion address of the server.","Этот адрес — вход через обычный интернет за Cloudflare. С Tor приложение использует onion-адрес сервера."],"err.tor_off_first":["Save the settings with Tor off before testing without Tor.","Сначала сохраните настройки с выключенным Tor, потом проверяйте без Tor."],"err.tor_on_first":["Save the settings with Tor on before testing through Tor, so your bridges are used.","Сначала сохраните настройки с включённым Tor, потом проверяйте через Tor, чтобы использовались ваши мосты."],"dlg.tor_off":["Turn off Tor?","Выключить Tor?"],"dlg.tor_off_text":["Without Tor your IP address becomes visible to the server and to Cloudflare, which carries the clearnet connection. Your provider also sees that you connect to Aegis.","Без Tor ваш IP-адрес становится виден серверу и Cloudflare, через который идёт подключение. Ваш провайдер тоже видит, что вы подключаетесь к Aegis."],"dlg.tor_off_ok":["Turn off Tor","Выключить Tor"],"upd.title":["Updates","Обновления"],"upd.auto":["Install updates automatically","Устанавливать обновления автоматически"],"upd.note":["Updates are signed with the Aegis release key and downloaded through the same route as messages. A verified update installs when Aegis locks or closes.","Обновления подписаны ключом выпусков Aegis и загружаются тем же маршрутом, что и сообщения. Проверенное обновление устанавливается, когда Aegis блокируется или закрывается."],"upd.version":["Version","Версия"],"upd.checking":["Checking for updates…","Проверяю обновления…"],"upd.available":["New version available:","Доступна новая версия:"],"upd.downloading":["Downloading version","Загружаю версию"],"upd.ready":["Ready to install: version","Готова к установке версия"],"upd.ready_when":["It installs when Aegis locks or closes.","Она установится, когда Aegis заблокируется или закроется."],"upd.required":["This version is no longer supported, restart to update.","Эта версия больше не поддерживается, перезапустите для обновления."],"upd.failed":["Could not check for updates.","Не удалось проверить обновления."],"upd.bad_sig":["Update refused: the signature is not valid.","Обновление отклонено: подпись недействительна."],"upd.bad_file":["Update refused: the file does not match the signed manifest.","Обновление отклонено: файл не совпадает с подписанным манифестом."],"upd.rollback":["Update refused: the server offered an older release.","Обновление отклонено: сервер предложил более старый выпуск."],"upd.check":["Check now","Проверить сейчас"],"upd.download":["Download","Загрузить"],"upd.restart":["Restart and update","Перезапустить и обновить"],"err.tor_boot":["Tor is still connecting. Nothing is sent until it is ready.","Tor ещё подключается. Пока он не готов, ничего не отправляется."],"err.server_key_changed":["The server key changed.","Ключ сервера изменился."],"err.server_key_unset":["The server key is not confirmed yet. Check the connection.","Ключ сервера ещё не подтверждён. Проверьте подключение."],"chan.official_off":["Official channel (not available yet)","Официальный канал (пока недоступен)"],"key.title":["Server key changed","Ключ сервера изменился"],"key.text":["This server now shows a different transport key than the one pinned on first use. Someone may be intercepting the connection, or the server was reinstalled. Nothing is sent or received. Lock the app and ask the server operator before continuing.","Сервер теперь показывает другой транспортный ключ, чем тот, что был запомнен при первом подключении. Возможно, соединение перехватывают, либо сервер переустановили. Ничего не отправляется и не принимается. Заблокируйте приложение и уточните у администратора сервера."],"err.needs_update":["This contact needs to update the app","Контакту нужно обновить приложение"],"err.request_mismatch":["That username does not match this key","Это имя пользователя не соответствует ключу"],"chat.undecryptable":["Some messages could not be decrypted","Некоторые сообщения не удалось расшифровать"],"req.title":["Message request","Запрос на переписку"],"req.note":["Someone you have not added wrote to you. Nothing is trusted yet. Enter the username you expect and it is accepted only if its published key is this one.","Вам написал тот, кого вы не добавляли. Пока ему ничего не доверяется. Введите ожидаемое имя пользователя: оно будет принято, только если его опубликованный ключ совпадает с этим."],"req.fingerprint":["Key fingerprint","Отпечаток ключа"],"req.username":["Username","Имя пользователя"],"req.accept":["Accept","Принять"],"req.block":["Block","Заблокировать"],"key.reset":["Reset pinned key","Сбросить запомненный ключ"],"key.reset_title":["Reset the pinned server key?","Сбросить запомненный ключ сервера?"],"key.reset_warn":["Only do this if you know the server was reinstalled. Otherwise someone may be intercepting your connection.","Делайте это, только если точно знаете, что сервер переустановили. Иначе кто-то может перехватывать ваше соединение."],"key.reset_do":["Yes, reset the key","Да, сбросить ключ"],"key.lock":["Lock","Заблокировать"],"dlg.clear_text":["All messages in this chat are removed from this device.","Все сообщения в этом чате будут удалены на этом устройстве."],"date.today":["Today","Сегодня"],"date.yesterday":["Yesterday","Вчера"],"err.no_channel":["Unknown channel.","Неизвестный канал."],"err.channel_readonly":["Only the owner can post in this channel.","Писать в этот канал может только владелец."],"err.channel_title":["Enter a channel name (up to 64 characters).","Введите название канала (до 64 символов)."],"err.about_long":["The text is too long (up to 140 characters).","Текст слишком длинный (до 140 символов)."],"err.channel_big":["A channel can have at most 200 subscribers.","В канале не больше 200 подписчиков."],"err.media_big":["The file is too large.","Файл слишком большой."],"err.media_type":["This file type is not supported.","Этот тип файла не поддерживается."],"err.media_bad":["The file could not be read.","Не удалось прочитать файл."],"stat.tor_off":["Tor off","Tor выкл."],"stat.onion":["Onion","Onion"],"stat.onion_tip":["Tor is connected and the app reaches the server through its onion address.","Tor подключён, приложение подключается к серверу через onion-адрес."],"stat.e2ee":["E2EE","E2EE"],"stat.e2ee_tip":["Messages are end-to-end encrypted.","Сообщения защищены сквозным шифрованием."],"stat.pin":["PIN","PIN"],"stat.nopin":["No PIN","Без PIN"],"stat.lock_tip":["App lock. Click to open Security and privacy.","Блокировка приложения. Нажмите, чтобы открыть «Безопасность и приватность»."],"guide.open":["Open","Открыть"],"guide.back":["Back","Назад"],"guide.next":["Next","Далее"],"guide.done":["Done","Готово"],"guide.skip":["Skip","Пропустить"],"guide.show":["Show the guide","Показать обучение"],"guide.welcome":["A quick tour","Короткое знакомство"],"guide.welcome_text":["Where things are and how to turn on protection. It takes a minute, and you can skip it.","Где что находится и как включить защиту. Это займёт минуту, можно пропустить."],"guide.settings":["Settings","Настройки"],"guide.settings_text":["The menu button opens contacts, new chats and Settings. Settings start with Security and privacy, then Network and Tor, Appearance, Notifications and Account.","Кнопка меню открывает контакты, новые чаты и настройки. Настройки начинаются с раздела «Безопасность и приватность», дальше «Сеть и Tor», «Оформление», «Уведомления» и «Аккаунт»."],"guide.security":["Turn on protection","Включите защиту"],"guide.security_text":["In Security and privacy set a PIN to lock the app, keep screen capture protection on and hide names in notifications. The lock indicator shows whether a PIN is set.","В разделе «Безопасность и приватность» задайте PIN для блокировки, оставьте защиту от снимков экрана включённой и скройте имена в уведомлениях. Индикатор замка показывает, задан ли PIN."],"guide.tor":["Tor and bridges","Tor и мосты"],"guide.tor_text":["Tor hides your IP address from the server: the app connects to its onion address. Bridges are unlisted Tor relays that help where Tor is blocked. The Tor indicator shows the state; click it for network settings.","Tor скрывает ваш IP-адрес от сервера: приложение подключается к его onion-адресу. Мосты — это неопубликованные узлы Tor, они помогают там, где Tor заблокирован. Индикатор Tor показывает состояние, по нажатию открываются настройки сети."],"guide.contacts":["Adding contacts safely","Безопасное добавление контактов"],"guide.contacts_text":["Type @username in the search field to find a person. Get the username from them directly, then compare the safety number on their profile in person or over another channel.","Введите @ник в поле поиска, чтобы найти человека. Узнайте ник у него напрямую, затем сверьте код безопасности в его профиле лично или по другому каналу."],"guide.appearance":["Make it yours","Настройте под себя"],"guide.appearance_text":["Theme, motion, layout and message style are in Settings, Appearance. This guide can be opened again in Settings, About.","Тема, анимация, расположение и стиль сообщений — в разделе «Оформление». Это обучение можно снова открыть в разделе «О программе»."],"look.title":["Theme","Тема"],"look.theme":["Accent","Акцент"],"look.theme_mono":["Graphite","Графит"],"look.theme_ocean":["Ocean","Океан"],"look.theme_dusk":["Dusk","Сумерки"],"look.theme_aurora":["Aurora","Сияние"],"look.theme_ember":["Ember","Угли"],"look.theme_slate":["Slate","Сланец"],"look.theme_custom":["Custom","Свой"],"look.color":["Color","Цвет"],"look.two_colors":["Use two colors","Два цвета"],"look.custom_note":["Pick two or three colors for your own gradient. It colors buttons, your messages and the header.","Выберите два или три цвета для своего градиента. Он окрашивает кнопки, ваши сообщения и шапку."],"look.pv_name":["Preview","Предпросмотр"],"look.pv_in":["Did the photos arrive?","Фото дошли?"],"look.pv_out":["Yes, all of them. Thanks!","Да, все. Спасибо!"],"look.animated":["Moving gradient background","Движущийся градиентный фон"],"look.animated_note":["A slow, dim gradient behind the chats. Off when motion is off.","Медленный приглушённый градиент за чатами. Выключен, если анимация выключена."],"look.motion_title":["Motion","Анимация"],"look.motion":["Animations","Анимации"],"look.motion_off":["Off","Выкл."],"look.motion_subtle":["Subtle","Мягкие"],"look.motion_full":["Full","Полные"],"look.motion_note":["When reduced motion is on in Windows, animations stay off.","Если в Windows включено уменьшение анимации, анимации остаются выключенными."],"look.depth":["Depth effect","Эффект глубины"],"look.depth_note":["Cards and messages tilt slightly toward the pointer.","Карточки и сообщения слегка наклоняются за указателем."],"look.layout":["Layout","Расположение"],"look.list":["Chat list","Список чатов"],"look.list_left":["Left","Слева"],"look.list_right":["Right","Справа"],"look.list_top":["Top","Сверху"],"look.density":["Density","Плотность"],"look.density_comfortable":["Comfortable","Свободно"],"look.density_compact":["Compact","Компактно"],"look.width_note":["Drag the edge of the chat list to change its width.","Перетащите край списка чатов, чтобы изменить его ширину."],"look.messages":["Messages","Сообщения"],"look.bubble":["Bubbles","Пузыри"],"look.bubble_rounded":["Rounded","Скруглённые"],"look.bubble_sharp":["Sharp","Острые"],"look.bubble_minimal":["Minimal","Минимальные"],"look.radius":["Corner radius","Радиус углов"],"look.font":["Text size","Размер текста"],"look.wallpaper":["Chat background","Фон чата"],"look.wallpaper_none":["Black","Чёрный"],"look.wallpaper_solid":["Solid","Цвет"],"look.wallpaper_gradient":["Gradient","Градиент"],"look.avatar":["Avatars","Аватары"],"look.avatar_circle":["Circle","Круг"],"look.avatar_rounded":["Rounded","Скруглённые"],"look.avatar_square":["Square","Квадрат"],"look.reset":["Reset to default","Сбросить оформление"],"group.members_1":["member","участник"],"group.members_2":["members","участника"],"media.none":["No photos or videos yet.","Фото и видео пока нет."],"d.upd_none":["You have the latest version.","У вас последняя версия."],"d.delete_ok":["Delete","Удалить"],"d.idle":["Lock after idle, minutes","Блокировать после простоя, мин"],"d.socks5":["SOCKS5 proxy, host:port","SOCKS5-прокси, host:port"],"d.flash":["Flash the taskbar on new messages","Мигать на панели задач"],"d.flash_note":["Message text is not shown.","При новых сообщениях; текст не показывается."],"d.delete_here":["Delete from this device","Удалить с этого устройства"],"d.server":["Server","Сервер"],"d.splash_a":["NETWORK INTERCEPTED","СЕТЬ ПЕРЕХВАЧЕНА"],"d.splash_b":["EXCEPT THIS CHANNEL","КРОМЕ ЭТОГО КАНАЛА"],"d.onb1":["Keys stay on your device. The server sees only the queue and the time.","Ключи остаются на устройстве. Сервер видит только очередь и время."],"d.onb2":["Compare the 30-digit safety number.","Сверьте 30-значный номер безопасности."],"d.onb3":["Disappearing messages, Tor by default, cover traffic.","Исчезающие сообщения, Tor по умолчанию, маскирующий трафик."],"d.start":["Start","Начать"],"d.chats":["Chats","Чаты"],"d.sound":["Sound","Звук"],"d.verify":["Verify","Проверка"],"d.about_short":["About","О себе"],"d.pin4":["4 digits","4 цифры"],"d.pin6":["6 digits","6 цифр"],"d.erase":["Erase","Стереть"],"d.show_secret":["Show","Показать"],"d.copied":["Copied.","Скопировано."],"d.compressed":["compressed to {w}×{h} · metadata removed · {kb} KB","сжато до {w}×{h} · метаданные удалены · {kb} КБ"],"d.post1":["Aegis 0.2.5. Tor is now built in and on by default. The app reaches the server through its onion address and sends nothing until Tor is connected. Where Tor is blocked, turn on bridges: Snowflake, obfs4 or your own lines.","Aegis 0.2.5. Tor теперь встроен в приложение и включён по умолчанию. Aegis подключается к серверу через onion-адрес и ничего не отправляет, пока Tor не подключился. Там, где Tor заблокирован, включите мосты: Snowflake, obfs4 или свои строки."],"d.post2":["PIN and duress. Unlock with 4 or 6 digits instead of the password. After five wrong tries the PIN stops working and only the password opens the vault. A duress PIN erases the account from the device and shows the usual wrong-PIN message.","PIN и принуждение. Входите четырьмя или шестью цифрами вместо пароля. После пяти неверных попыток PIN перестаёт действовать, и хранилище открывает только пароль. PIN принуждения стирает аккаунт с устройства и показывает обычное сообщение о неверном PIN."],"d.post3":["Media compression. Photos are re-encoded as JPEG, at most 1600 px on the long side, with EXIF and other metadata removed. Videos lose their metadata too. Files up to 40 MB.","Сжатие медиа. Фото перекодируются в JPEG не больше 1600 px по длинной стороне, EXIF и другие метаданные удаляются. Из видео метаданные тоже вычищаются. Файлы до 40 МБ."],"d.post4":["Cover traffic. While the app is open it talks to the network on its own schedule: when there is no real request, a dummy one of the same size goes out, so the server cannot tell when you are really talking. Off, Normal or Strong in Network and Tor. It stops while Aegis is locked or minimized.","Маскирующий трафик. Пока приложение открыто, оно ходит в сеть по своему расписанию: если настоящего запроса нет, уходит пустой такого же размера, и сервер не видит, когда вы действительно общаетесь. Выключен, Обычный или Усиленный — в разделе «Сеть и Tor». Пока Aegis заблокирован или свёрнут, трафик останавливается."],"d.cover_real":["real","настоящие"],"d.cover_dummy":["dummy","пустые"],"d.gate_create":["Creating your account","Создаём аккаунт"],"d.gate_open":["Signing in","Входим"],"d.gate_done":["Account created","Аккаунт создан"],"d.gate_keys":["Generating keys","Генерация ключей"],"d.gate_pow":["Registration puzzle","Задача регистрации"],"d.zoom_in":["Zoom in","Увеличить"],"d.zoom_out":["Zoom out","Уменьшить"],"look.wallpaper_photo":["Photo","Фото"],"look.photo_pick":["Choose photo","Выбрать фото"],"look.scope":["Where","Где"],"look.scope_chat":["In chats","В чатах"],"look.scope_full":["Everywhere","Везде"],"look.dim":["Dimming","Затемнение"],"look.effect":["Screen effect","Эффект на экране"],"look.fx_none":["None","Нет"],"look.fx_rain":["Rain","Дождь"],"look.fx_snow":["Snow","Снег"],"look.fx_dust":["Dust","Пыль"],"look.fx_embers":["Embers","Искры"],"look.fx_stars":["Stars","Звёзды"],"d.lock_title":["Enter your PIN","Введите PIN"],"d.use_password":["Password","Пароль"],"d.lock_ok":["OK","ОК"]};
let LANG = 'ru';
try { LANG = localStorage.getItem('aegis.lang') === 'en' ? 'en' : 'ru'; } catch (e) { LANG = 'ru'; }
function t(k) { const v = I18N[k]; return v ? v[LANG === 'en' ? 0 : 1] : k; }
function tf(k, vars) { return t(k).replace(/\{(\w+)\}/g, (_, n) => (vars && n in vars ? vars[n] : '')); }
// errors follow the app: text (detail); ok messages: text: detail
const errText = (k, d) => t(k) + (d != null && d !== '' ? ' (' + d + ')' : '');
const okText = (k, d) => t(k) + (d != null && d !== '' ? ': ' + d : '');

// ── motion ───────────────────────────────────────────────
const E = {
  scene: 'cubic-bezier(.16,1,.3,1)',
  out: 'cubic-bezier(.2,.7,.2,1)',
  soft: 'cubic-bezier(.65,0,.35,1)',
  back: 'cubic-bezier(.34,1.56,.64,1)',
};
/* A damped spring sampled into a CSS linear() easing, for WAAPI moves that should
   overshoot a little and settle like Spring does (k = stiffness, z = damping ratio). */
function springCurve(k, z) {
  const w = Math.sqrt(k), wd = w * Math.sqrt(1 - z * z), T = 5 / (z * w), n = 48;
  const x = s => 1 - Math.exp(-z * w * s) * (Math.cos(wd * s) + (z * w / wd) * Math.sin(wd * s));
  const pts = Array.from({ length: n + 1 }, (_, i) => (i === n ? 1 : +x(T * i / n).toFixed(4)));
  return { easing: `linear(${pts.join(',')})`, duration: Math.round(T * 1000) };
}
const RMQ = matchMedia('(prefers-reduced-motion: reduce)');
let reduced = RMQ.matches;
const motionSubs = new Set();
function setReduced(v) {
  reduced = !!v;
  document.documentElement.classList.toggle('rm', reduced);
  motionSubs.forEach(f => f(reduced));
}
/* The OS "reduce motion" switch only calms the flicker (html.calm: no glitch,
   CRT, grain); movement stays, because the prototype is about motion.
   Full stillness is the #still link or setReduced(true). */
const calmOS = () => document.documentElement.classList.toggle('calm', RMQ.matches);
RMQ.addEventListener('change', calmOS);
calmOS();
reduced = location.hash === '#still';
setReduced(reduced);

/* WAAPI wrapper: resolves when done, instant under reduced motion. */
function anim(el, frames, opts = {}) {
  if (!el || !el.animate) return Promise.resolve();
  const o = typeof opts === 'number' ? { duration: opts } : { ...opts };
  if (reduced) { o.duration = 1; o.delay = 0; }
  o.easing = o.easing || E.scene;
  const a = el.animate(frames, o);
  return a.finished.then(() => a, () => a);
}

/* Spring sampled into a CSS linear() easing, so WAAPI can play real springs.
   k is stiffness (the brief: 260-320), z the damping ratio. */
const LINEAR_OK = typeof CSS !== 'undefined' && CSS.supports && CSS.supports('animation-timing-function', 'linear(0, 1)');
const springCache = new Map();
function springEase(k = 280, z = 0.62) {
  const key = k + ':' + z;
  if (springCache.has(key)) return springCache.get(key);
  const c = 2 * Math.sqrt(k) * z, dt = 1 / 600;
  let x = 0, v = 0, t = 0;
  const pts = [0];
  while (t < 2.4) {
    for (let i = 0; i < 10; i++) { const a = -k * (x - 1) - c * v; v += a * dt; x += v * dt; t += dt; }
    pts.push(x);
    if (t > 0.2 && Math.abs(x - 1) < 0.0015 && Math.abs(v) < 0.02) break;
  }
  pts[pts.length - 1] = 1;
  const step = Math.max(1, Math.round(pts.length / 48));
  const thin = pts.filter((_, i) => i % step === 0 || i === pts.length - 1);
  const out = LINEAR_OK
    ? { easing: 'linear(' + thin.map(p => +p.toFixed(4)).join(',') + ')', duration: Math.round(t * 1000) }
    : { easing: E.back, duration: 520 };
  springCache.set(key, out);
  return out;
}

/* Numeric springs stepped by rAF, for things that follow the pointer
   (segment pill, list highlight, sheet drag release). */
class Spring {
  constructor(x = 0, k = 290, z = 0.7) { this.x = x; this.v = 0; this.to = x; this.k = k; this.c = 2 * Math.sqrt(k) * z; }
  step(h) { const a = -this.k * (this.x - this.to) - this.c * this.v; this.v += a * h; this.x += this.v * h; }
  get rest() { return Math.abs(this.v) < 0.05 && Math.abs(this.x - this.to) < 0.05; }
  snap(v) { if (v != null) this.to = v; this.x = this.to; this.v = 0; }
}
function runSprings(springs, render, done) {
  let last = performance.now(), id = 0, live = true;
  const f = now => {
    const dt = Math.min(0.034, (now - last) / 1000);
    last = now;
    const n = Math.ceil(dt / 0.004), hh = dt / n;
    for (const s of springs) for (let i = 0; i < n; i++) s.step(hh);
    if (reduced || springs.every(s => s.rest)) { springs.forEach(s => s.snap()); render(); live = false; done && done(); return; }
    render();
    id = requestAnimationFrame(f);
  };
  id = requestAnimationFrame(f);
  return { stop() { if (live) cancelAnimationFrame(id); live = false; }, get live() { return live; } };
}

// ── text effects ─────────────────────────────────────────
const GLYPHS = '█▓▒░#%&@';
const HEX = '0123456789abcdef';
/* glyph decode: block glyphs settle into the text, 1100 ms */
function decode(el, text, dur = 1100) {
  text = text == null ? el.textContent : String(text);
  if (el._dec) el._dec.cancel = true;
  if (reduced || !text) { el.textContent = text; return Promise.resolve(); }
  const chars = [...text];
  const at = chars.map((ch, i) => (/\s/.test(ch) ? 0 : (0.12 + 0.62 * (i / Math.max(1, chars.length - 1)) + Math.random() * 0.22) * dur));
  const job = { cancel: false };
  el._dec = job;
  el.setAttribute('aria-label', text);
  const t0 = performance.now();
  return new Promise(res => {
    let n = 0;
    const f = now => {
      if (job.cancel) return res();
      const e = now - t0;
      if (e >= dur) { el.textContent = text; el.removeAttribute('aria-label'); el._dec = null; return res(); }
      if (n++ % 2 === 0) el.textContent = chars.map((ch, i) => (e >= at[i] ? ch : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join('');
      requestAnimationFrame(f);
    };
    requestAnimationFrame(f);
  });
}
/* hex scramble on send: plain → cipher → plain, about 1.3 s */
function scramble(el, text, dur = 1300) {
  if (reduced) { el.textContent = text; return Promise.resolve(); }
  const chars = [...text], N = chars.length;
  if (N > 900) { el.textContent = text; return anim(el, [{ opacity: 0.4 }, { opacity: 1 }], { duration: 500 }).then(() => {}); }
  const a = chars.map(() => Math.random() * 0.34), b = chars.map(() => 0.62 + Math.random() * 0.34);
  const t0 = performance.now();
  return new Promise(res => {
    let n = 0;
    const f = now => {
      const p = (now - t0) / dur;
      if (p >= 1) { el.textContent = text; return res(); }
      if (n++ % 2 === 0) el.textContent = chars.map((ch, i) => (/\s/.test(ch) ? ch : p < a[i] || p > b[i] ? ch : HEX[(Math.random() * 16) | 0])).join('');
      requestAnimationFrame(f);
    };
    requestAnimationFrame(f);
  });
}
/* letters fall apart into ash, then the row collapses (1 s + 0.4 s) */
function ash(el, opts = {}) {
  const text = el.textContent;
  if (reduced || !text) return Promise.resolve();
  const max = opts.max || 220;
  el.textContent = '';
  const spans = [];
  const chars = [...text];
  chars.forEach((ch, i) => {
    if (i >= max) { if (i === max) el.append(h('span', { style: { opacity: 0.5 } }, chars.slice(max).join(''))); return; }
    if (ch === '\n') { el.append('\n'); return; }
    const s = h('span.ashc', ch === ' ' ? ' ' : ch);
    spans.push(s);
    el.append(s);
  });
  const cs = getComputedStyle(el), c0 = cs.color, rs = getComputedStyle(document.documentElement);
  const hot = rs.getPropertyValue('--bone').trim() || '#eeeef1', dim = rs.getPropertyValue('--dim').trim() || '#5b5c63';
  const jobs = spans.map((s, i) => {
    const dx = (Math.random() - 0.5) * 44, dy = -(18 + Math.random() * 46), r = (Math.random() - 0.5) * 140;
    return anim(s, [
      { transform: 'none', opacity: 1, filter: 'blur(0)', color: c0 },
      { offset: 0.25, color: hot },
      { transform: `translate(${dx}px,${dy}px) rotate(${r}deg) scale(.4)`, opacity: 0, filter: 'blur(2px)', color: dim },
    ], { duration: 640 + Math.random() * 220, delay: (i / Math.max(1, spans.length)) * 300 + Math.random() * 60, easing: E.out, fill: 'forwards' });
  });
  return Promise.all(jobs).then(() => {});
}
function collapse(el, dur = 400) {
  const r = el.getBoundingClientRect();
  el.style.overflow = 'hidden';
  return anim(el, [
    { height: r.height + 'px', opacity: getComputedStyle(el).opacity },
    { height: '0px', opacity: 0, paddingTop: '0px', paddingBottom: '0px', marginTop: '0px', marginBottom: '0px' },
  ], { duration: dur, easing: E.soft, fill: 'forwards' }).then(() => el.remove());
}
function shake(el) {
  if (!el) return;
  el.style.animation = 'none';
  void el.offsetWidth;
  el.style.animation = `shake var(--d-shake) ${E.out}`;
  el.addEventListener('animationend', () => { el.style.animation = ''; }, { once: true });
}

// ── controls ─────────────────────────────────────────────
/* Segmented control with a spring pill that squashes with speed.
   el: .seg with buttons [data-v]; returns { set(v) } */
function seg(el, value, onChange) {
  let pill = el.querySelector('.pill');
  if (!pill) { pill = h('i.pill', { 'aria-hidden': 'true' }); el.prepend(pill); }
  const btns = () => [...el.querySelectorAll(':scope > button')];
  el.setAttribute('role', el.getAttribute('role') || 'radiogroup');
  const sx = new Spring(0, 290, 0.66), sw = new Spring(0, 290, 0.8);
  let run = null, first = true;
  const render = () => {
    const v = Math.abs(sx.v);
    const sq = Math.min(0.16, v / 5200);
    pill.style.width = Math.max(0, sw.x) + 'px';
    pill.style.transform = `translateX(${sx.x}px) scale(${1 + sq * 0.6},${1 - sq})`;
  };
  const place = (instant) => {
    const b = btns().find(x => x.dataset.v === String(value));
    if (!b) { pill.style.opacity = 0; return; }
    pill.style.opacity = 1;
    if (el.classList.contains('wrap')) { pill.style.top = b.offsetTop + 'px'; pill.style.height = b.offsetHeight + 'px'; pill.style.bottom = 'auto'; }
    sx.to = b.offsetLeft; sw.to = b.offsetWidth;
    if (instant || first || reduced) { sx.snap(); sw.snap(); render(); first = false; return; }
    if (!run || !run.live) run = runSprings([sx, sw], render);
  };
  const mark = () => btns().forEach(b => {
    const on = b.dataset.v === String(value);
    b.setAttribute(el.getAttribute('role') === 'tablist' ? 'aria-selected' : 'aria-checked', on);
    b.setAttribute('role', el.getAttribute('role') === 'tablist' ? 'tab' : 'radio');
    b.tabIndex = on ? 0 : -1;
  });
  el.addEventListener('click', e => {
    const b = e.target.closest('button');
    if (!b || b.parentElement !== el || b.disabled) return;
    if (b.dataset.v === String(value)) return;
    value = b.dataset.v; mark(); place(); onChange && onChange(value);
  });
  el.addEventListener('keydown', e => {
    if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
    const list = btns().filter(b => !b.disabled);
    let i = list.findIndex(b => b.dataset.v === String(value));
    i = e.key === 'Home' ? 0 : e.key === 'End' ? list.length - 1 : (i + (e.key === 'ArrowRight' ? 1 : -1) + list.length) % list.length;
    list[i].focus(); list[i].click(); e.preventDefault();
  });
  mark();
  requestAnimationFrame(() => place(true));
  new ResizeObserver(() => place(true)).observe(el);
  return { set(v, silent) { value = v; mark(); place(); if (!silent && onChange) onChange(v); }, get value() { return value; }, place };
}

/* Liquid toggle: the fill grows from the knob, the knob stretches on press and drag. */
function toggle(on, onChange, label) {
  const el = h('button.tg', { type: 'button', role: 'switch', 'aria-checked': String(!!on), 'aria-label': label || null },
    h('i.tg-fill'), h('i.tg-knob'));
  let x0 = null, moved = false;
  const set = v => { on = !!v; el.setAttribute('aria-checked', String(on)); };
  el.addEventListener('pointerdown', e => { x0 = e.clientX; moved = false; el.classList.add('drag'); el.setPointerCapture(e.pointerId); });
  el.addEventListener('pointermove', e => {
    if (x0 == null) return;
    const dx = e.clientX - x0;
    if (Math.abs(dx) > 8 && !moved) moved = true;
    if (moved && (dx > 0) !== on) { set(dx > 0); onChange && onChange(on); x0 = e.clientX; }
  });
  const end = () => { el.classList.remove('drag'); x0 = null; };
  el.addEventListener('pointerup', end);
  el.addEventListener('pointercancel', end);
  el.addEventListener('click', e => { if (moved) { moved = false; e.preventDefault(); return; } set(!on); onChange && onChange(on); });
  el.set = set;
  return el;
}

/* Floating-label field. opts: { label, type, value, mono, area, max, auto, name, inputmode, oninput } */
function field(o) {
  const id = uid('f');
  const input = o.area
    ? h('textarea', { id, rows: o.rows || 3, placeholder: ' ', maxlength: o.hardMax || null, spellcheck: 'false' })
    : h('input', { id, type: o.type || 'text', placeholder: ' ', autocomplete: o.auto || 'off', inputmode: o.inputmode || null, spellcheck: 'false', autocapitalize: 'off', maxlength: o.hardMax || null, name: o.name || null });
  if (o.value != null) input.value = o.value;
  const lab = h('span', o.label);
  const wrap = h('label.fld' + (o.mono ? '.mono' : ''), { for: id }, input, lab);
  const msg = h('p.fmsg', { id: id + '-m', 'aria-live': 'polite' });
  input.setAttribute('aria-describedby', id + '-m');
  let cnt = null;
  if (o.max) {
    cnt = h('span.cnt', { 'aria-hidden': 'true' });
    wrap.append(cnt);
    const upd = () => { const n = [...input.value].length; cnt.textContent = n + '/' + o.max; cnt.classList.toggle('over', n > o.max); };
    input.addEventListener('input', upd); upd();
  }
  if (o.type === 'password') {
    const eye = h('button.ib.bare.eye', { type: 'button', 'aria-label': t('d.show_secret'), 'aria-pressed': 'false' }, ico('eye'));
    eye.addEventListener('click', e => { e.preventDefault(); const show = input.type === 'password'; input.type = show ? 'text' : 'password'; eye.setAttribute('aria-pressed', String(show)); input.focus(); });
    wrap.append(eye);
  }
  input.addEventListener('input', () => { if (wrap.classList.contains('err')) { wrap.classList.remove('err'); msg.textContent = ''; input.removeAttribute('aria-invalid'); } o.oninput && o.oninput(input.value); });
  const box = h('div.fbox', wrap, msg);
  box.input = input; box.wrap = wrap; box.msg = msg; box.label = lab;
  box.error = text => { wrap.classList.add('err'); msg.className = 'fmsg'; msg.textContent = text || ''; input.setAttribute('aria-invalid', 'true'); shake(wrap); };
  box.ok = text => { wrap.classList.remove('err'); msg.className = 'fmsg ok'; msg.textContent = text || ''; };
  box.clear = () => { wrap.classList.remove('err'); msg.textContent = ''; input.removeAttribute('aria-invalid'); };
  if (cnt) box.count = () => input.dispatchEvent(new Event('input'));
  return box;
}

/* Button → spinner: the width folds into a circle in 500 ms */
function busy(btn, on) {
  if (!btn) return;
  if (on) {
    if (btn._busy) return;
    btn._busy = true;
    const w = btn.offsetWidth, hgt = btn.offsetHeight;
    btn.dataset.w = w;
    btn.style.width = w + 'px';
    btn.classList.add('busy');
    btn.setAttribute('aria-busy', 'true');
    btn._a = btn.animate([{ width: w + 'px' }, { width: hgt + 'px' }], { duration: reduced ? 1 : 500, easing: E.soft, fill: 'forwards' });
  } else {
    if (!btn._busy) return;
    btn._busy = false;
    const w = +btn.dataset.w || btn.offsetWidth;
    if (btn._a) btn._a.cancel();
    const a = btn.animate([{ width: btn.offsetHeight + 'px' }, { width: w + 'px' }], { duration: reduced ? 1 : 380, easing: E.scene });
    btn.classList.remove('busy');
    btn.removeAttribute('aria-busy');
    a.finished.then(() => { btn.style.width = ''; }, () => {});
  }
}

// ── flash, live region ───────────────────────────────────
function announce(text) {
  const live = $('#live');
  if (!live) return;
  live.textContent = '';
  setTimeout(() => { live.textContent = text; }, 30);
}
function flash(text, kind = 'err', ms = 3800) {
  let box = $('.flashes');
  if (!box) { box = h('div.flashes'); ENTRY.append(box); }
  const el = h('div.flash' + (kind === 'ok' ? '.ok' : ''), { role: 'status' }, h('span', text));
  box.append(el);
  announce(text);
  anim(el, [{ opacity: 0, transform: 'translateY(14px) scale(.98)' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
  while (box.children.length > 3) box.firstElementChild.remove();
  setTimeout(() => anim(el, [{ opacity: 1 }, { opacity: 0, transform: 'translateY(8px)' }], { duration: 260, easing: E.out, fill: 'forwards' }).then(() => el.remove()), ms);
  return el;
}

// ── layer: sheets, dialogs, menus ────────────────────────
const isDesk = () => innerWidth >= 900;
const layer = () => $('#layer') || ENTRY;
let openSheets = [];
function trapFocus(root, e) {
  const f = $$('button:not([disabled]), [href], input:not([disabled]), textarea:not([disabled]), select, [tabindex]:not([tabindex="-1"])', root).filter(x => x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { last.focus(); e.preventDefault(); }
  else if (!e.shiftKey && document.activeElement === last) { first.focus(); e.preventDefault(); }
}
/* Sheet: bottom sheet with a spring and swipe-down on phones,
   a 440 px card in the middle on desktop, same spring. */
function sheet({ title, body, foot, onClose, cls = '', focus = true, label }) {
  const back = document.activeElement;
  const scrim = h('div.scrim');
  const close = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const grab = h('button.grab', { type: 'button', 'aria-label': t('common.close'), tabIndex: -1 });
  const head = h('div.sh-head', h('h2.t-sheet', { id: uid('sh') }, title), close);
  const el = h('div.sheet' + (cls ? '.' + cls : ''), { role: 'dialog', 'aria-modal': 'true' }, grab, head, h('div.sh-body', body), foot ? h('div.sh-foot', foot) : null);
  el.setAttribute('aria-labelledby', head.firstChild.id);
  if (label) el.setAttribute('aria-label', label);
  layer().append(scrim, el);
  const sp = springEase(isDesk() ? 300 : 270, isDesk() ? 0.72 : 0.78);
  anim(scrim, [{ opacity: 0 }, { opacity: 1 }], { duration: 300, easing: E.out });
  anim(el, isDesk()
    ? [{ opacity: 0, transform: 'translateY(26px) scale(.965)' }, { opacity: 1, transform: 'none' }]
    : [{ transform: 'translateY(100%)' }, { transform: 'none' }], { duration: sp.duration, easing: sp.easing });
  let done = false;
  const api = {
    el, body: el.querySelector('.sh-body'),
    async close(v) {
      if (done) return; done = true;
      openSheets = openSheets.filter(s => s !== api);
      document.removeEventListener('keydown', onKey, true);
      anim(scrim, [{ opacity: 1 }, { opacity: 0 }], { duration: 240, easing: E.out, fill: 'forwards' });
      await anim(el, isDesk()
        ? [{ opacity: 1, transform: getComputedStyle(el).transform === 'none' ? 'none' : getComputedStyle(el).transform }, { opacity: 0, transform: 'translateY(18px) scale(.97)' }]
        : [{ transform: getComputedStyle(el).transform === 'none' ? 'none' : getComputedStyle(el).transform }, { transform: 'translateY(105%)' }], { duration: 300, easing: E.soft, fill: 'forwards' });
      scrim.remove(); el.remove();
      if (back && back.isConnected) back.focus({ preventScroll: true });
      onClose && onClose(v);
    },
  };
  const onKey = e => {
    if (openSheets[openSheets.length - 1] !== api) return;
    if (e.key === 'Escape') { e.stopPropagation(); api.close(); }
    if (e.key === 'Tab') trapFocus(el, e);
  };
  document.addEventListener('keydown', onKey, true);
  scrim.addEventListener('click', () => api.close());
  close.addEventListener('click', () => api.close());
  grab.addEventListener('click', () => api.close());
  // swipe down to close (phone)
  let y0 = null, dy = 0, t0 = 0;
  const startDrag = e => { if (isDesk() || e.button > 0) return; y0 = e.clientY; dy = 0; t0 = performance.now(); el.setPointerCapture(e.pointerId); el.style.transition = 'none'; };
  [grab, head].forEach(x => x.addEventListener('pointerdown', e => { if (e.target.closest('button') && e.target !== grab) return; startDrag(e); }));
  el.addEventListener('pointermove', e => { if (y0 == null) return; dy = Math.max(0, e.clientY - y0); el.style.transform = `translateY(${dy}px)`; });
  const endDrag = () => {
    if (y0 == null) return;
    const v = dy / Math.max(1, performance.now() - t0);
    y0 = null;
    if (dy > el.offsetHeight * 0.28 || v > 0.6) api.close();
    else { const s = springEase(300, 0.7); anim(el, [{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: s.duration, easing: s.easing }).then(() => { el.style.transform = ''; }); }
  };
  el.addEventListener('pointerup', endDrag);
  el.addEventListener('pointercancel', endDrag);
  openSheets.push(api);
  if (focus) requestAnimationFrame(() => { const f = el.querySelector('.sh-body input, .sh-body textarea') || close; f.focus({ preventScroll: true }); });
  return api;
}
/* Dialog = a small sheet with a text and two buttons. Resolves true / false. */
function ask({ title, text, ok, danger = true, extra }) {
  return new Promise(res => {
    let val = false;
    const yes = h('button.btn.wide' + (danger ? '.danger' : ''), { type: 'button' }, ok);
    const no = h('button.btn.ghost.wide', { type: 'button' }, t('common.cancel'));
    const s = sheet({ title, body: [text ? h('p.note', text) : null, extra || null], foot: [yes, no], cls: 'dlg', onClose: () => res(val) });
    yes.addEventListener('click', async () => {
      if (extra && extra.check) { const okv = await extra.check(); if (!okv) return; }
      val = true; s.close(true);
    });
    no.addEventListener('click', () => s.close(false));
  });
}

/* Menu grows from the press point; items come in as a ladder (300-400 ms). */
let openMenu = null;
function menu(anchor, items, { align = 'end' } = {}) {
  if (openMenu) { const m = openMenu; m.close(); if (m.anchor === anchor) return; }
  const el = h('div.menu', { role: 'menu' });
  items.filter(Boolean).forEach(it => {
    if (it === '-') { el.append(h('hr')); return; }
    const b = h('button' + (it.danger ? '.danger' : ''), { type: 'button', role: 'menuitem' }, it.icon ? ico(it.icon) : null, h('span', it.label), it.value ? h('span.m-v', it.value) : null);
    b.addEventListener('click', () => { api.close(); it.run && it.run(); });
    el.append(b);
  });
  layer().append(el);
  const r = anchor.getBoundingClientRect(), mw = el.offsetWidth, mh = el.offsetHeight;
  let x = align === 'end' ? r.right - mw : r.left, y = r.bottom + 8;
  x = clamp(x, 12, innerWidth - mw - 12);
  if (y + mh > innerHeight - 12) y = Math.max(12, r.top - mh - 8);
  el.style.left = x + 'px';
  el.style.top = y + 'px';
  el.style.transformOrigin = `${clamp(r.left + r.width / 2 - x, 0, mw)}px ${r.top > y ? mh : 0}px`;
  anim(el, [{ opacity: 0, transform: 'scale(.55)' }, { opacity: 1, transform: 'none' }], { duration: 340, easing: E.scene });
  [...el.children].forEach((c, i) => anim(c, [{ opacity: 0, transform: 'translateY(-6px)' }, { opacity: 1, transform: 'none' }], { duration: 300, delay: 40 + i * 28, easing: E.out, fill: 'backwards' }));
  anchor.setAttribute('aria-expanded', 'true');
  const btns = () => $$('button', el);
  const onKey = e => {
    if (e.key === 'Escape') { api.close(); anchor.focus(); e.stopPropagation(); }
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      const l = btns(); let i = l.indexOf(document.activeElement);
      i = (i + (e.key === 'ArrowDown' ? 1 : -1) + l.length) % l.length; l[i].focus(); e.preventDefault();
    }
    if (e.key === 'Tab') api.close();
  };
  const onDown = e => { if (!el.contains(e.target) && !anchor.contains(e.target)) api.close(); };
  document.addEventListener('keydown', onKey, true);
  setTimeout(() => document.addEventListener('pointerdown', onDown, true));
  const api = {
    anchor,
    close() {
      if (openMenu !== api) return;
      openMenu = null;
      anchor.setAttribute('aria-expanded', 'false');
      document.removeEventListener('keydown', onKey, true);
      document.removeEventListener('pointerdown', onDown, true);
      anim(el, [{ opacity: 1 }, { opacity: 0, transform: 'scale(.92)' }], { duration: 160, easing: E.out, fill: 'forwards' }).then(() => el.remove());
    },
  };
  openMenu = api;
  requestAnimationFrame(() => btns()[0] && btns()[0].focus({ preventScroll: true }));
  return api;
}

/* Tilt card toward the pointer with a moving glare (card3d: ±14° / ±18°) */
function card3d(el, max = [14, 18]) {
  if (!el.querySelector(':scope > .glare')) el.append(h('i.glare', { 'aria-hidden': 'true' }));
  const rx = new Spring(0, 170, 0.75), ry = new Spring(0, 170, 0.75);
  let run = null;
  const render = () => { el.style.transform = `perspective(800px) rotateX(${rx.x}deg) rotateY(${ry.x}deg)`; };
  const go = () => { if (!run || !run.live) run = runSprings([rx, ry], render); };
  el.addEventListener('pointermove', e => {
    if (reduced || e.pointerType === 'touch') return;
    const r = el.getBoundingClientRect(), nx = (e.clientX - r.left) / r.width, ny = (e.clientY - r.top) / r.height;
    rx.to = (0.5 - ny) * 2 * max[0] * 0.5; ry.to = (nx - 0.5) * 2 * max[1] * 0.5;
    el.style.setProperty('--gx', nx * 100 + '%'); el.style.setProperty('--gy', ny * 100 + '%');
    go();
  });
  el.addEventListener('pointerleave', () => { rx.to = 0; ry.to = 0; go(); });
}

// ── time ─────────────────────────────────────────────────
const pad = (n, l = 2) => String(n).padStart(l, '0');
const hm = d => pad(d.getHours()) + ':' + pad(d.getMinutes());
const stamp = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
function dayLabel(d) {
  const now = new Date(), a = new Date(now.getFullYear(), now.getMonth(), now.getDate()), b = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const diff = Math.round((a - b) / 864e5);
  if (diff === 0) return t('date.today');
  if (diff === 1) return t('date.yesterday');
  return d.toLocaleDateString(LANG === 'en' ? 'en-GB' : 'ru-RU', { day: 'numeric', month: 'long' });
}

// ── storage: only per-viewer conveniences (language, particles) ──
const store = {
  get(k, d) { try { const v = localStorage.getItem('aegis.' + k); return v == null ? d : v; } catch (e) { return d; } },
  set(k, v) { try { localStorage.setItem('aegis.' + k, v); } catch (e) { /* private mode */ } },
};

// ── clipboard: inside a click handler, with a select-text fallback ──
async function copyText(text, fallbackEl) {
  try { await navigator.clipboard.writeText(text); return true; } catch (e) {
    if (fallbackEl) {
      const r = document.createRange(); r.selectNodeContents(fallbackEl);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
    }
    return false;
  }
}

// scene3d.js
'use strict';
/* 3D layer: one canvas (#gl) under the UI. An object follows its .obj3d
   anchor in the DOM every frame (spring-smoothed), a swarm of 480 cubes
   morphs one object into another, particles fill the background.
   Three.js comes from jsdelivr; without it (or without WebGL) the app still
   works and anchors get a flat line drawing. */
const AegisScene = (() => {
  const URL3 = '/vendor/three.module.min.js';
  const SV = d => `<svg viewBox="0 0 24 24" aria-hidden="true">${d}</svg>`;
  const FLAT = {
    shield: SV('<path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z"/><path d="M12 9.2a1.6 1.6 0 0 1 .7 3l.5 3.3h-2.4l.5-3.3a1.6 1.6 0 0 1 .7-3z"/>'),
    rings: SV('<circle cx="9" cy="12" r="5.5"/><circle cx="15" cy="12" r="5.5"/>'),
    ash: SV('<circle cx="12" cy="12" r="7" stroke-dasharray="1.6 2.4"/>'),
    cube: SV('<path d="M12 3.5l7.5 4.2v8.6L12 20.5l-7.5-4.2V7.7zM4.5 7.7L12 12l7.5-4.3M12 12v8.5"/>'),
  };
  const want = { name: null, anchor: null };
  let pmode = store.get('particles', 'dust'), prog = 0, failed = false, g3 = null, resting = false;
  function flat(anchor, name) {
    if (!anchor) return;
    anchor.classList.add('flat');
    anchor.innerHTML = name && FLAT[name] ? FLAT[name] : '';
  }
  const ready = (async () => {
    try {
      const probe = document.createElement('canvas');
      if (!(probe.getContext('webgl2') || probe.getContext('webgl'))) throw new Error('no webgl');
      const THREE = await import(URL3);
      g3 = build(THREE);
      g3.particles(pmode);
      if (want.name) g3.show(want.name, want.anchor, { assemble: true });
      g3.progress(prog);
      if (resting) g3.rest(0);
      return true;
    } catch (e) {
      failed = true;
      if (want.name) flat(want.anchor, want.name);
      return false;
    }
  })();
  return {
    ready,
    get live() { return !!g3; },
    show(name, anchor, o = {}) {
      want.name = name; want.anchor = anchor; resting = false;
      if (g3) g3.show(name, anchor, o); else if (failed) flat(anchor, name);
    },
    scatter() { want.name = null; want.anchor = null; if (g3) g3.scatter(); },
    /* nothing of the scene can be seen (opaque panes cover it): stop drawing after ms;
       the next show() brings it back */
    rest(ms = 0) { resting = true; if (g3) g3.rest(ms); },
    particles(m) { pmode = m; if (g3) g3.particles(m); },
    progress(p) { prog = p; if (g3) g3.progress(p); },
    pulse() { if (g3) g3.pulse(); },
    snapshot() { return g3 ? g3.snapshot() : null; },
  };

  function build(THREE) {
    const canvas = document.getElementById('gl');
    const LITE = Math.min(screen.width, screen.height) < 600 || /Android|iPhone/.test(navigator.userAgent);
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: !LITE, alpha: true, powerPreference: LITE ? 'default' : 'high-performance' });
    renderer.setClearColor(0x000000, 0);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;
    const scene = new THREE.Scene();
    const FOV = 35, CZ = 10, N = LITE ? 300 : 480, RIM = 0.9;
    const camera = new THREE.PerspectiveCamera(FOV, 1, 0.1, 80);
    camera.position.z = CZ;
    let W = 1, H = 1, K = 0.01;

    // environment: a dark room, soft boxes, a faint red strip low on the left (the rim)
    const envScene = new THREE.Scene();
    envScene.add(new THREE.Mesh(new THREE.BoxGeometry(30, 30, 30), new THREE.MeshBasicMaterial({ color: 0x030304, side: THREE.BackSide })));
    const panel = (w, hh, hexv, k, x, y, z) => {
      const m = new THREE.Mesh(new THREE.PlaneGeometry(w, hh), new THREE.MeshBasicMaterial({ color: new THREE.Color(hexv).multiplyScalar(k), side: THREE.DoubleSide }));
      m.position.set(x, y, z); m.lookAt(0, 0, 0); envScene.add(m);
      return m;
    };
    panel(9, 3, 0xffffff, 4, 0, 8, 4);
    panel(3, 9, 0xdde2ff, 1.6, -8, 1, 3);
    panel(3, 7, 0xffffff, 1, 8, 0, -3);
    const strip = panel(7, 1.6, 0xff1f3d, 0.8, -5, -7, 2);
    const pmrem = new THREE.PMREMGenerator(renderer);
    scene.environment = pmrem.fromScene(envScene, 0.04).texture;
    // the cube is flat metal: a face turned to the strip mirrors it whole and the cube goes red,
    // so the cube gets the same room without the strip (the rim light still edges it)
    strip.visible = false;
    const envCool = pmrem.fromScene(envScene, 0.04).texture;
    strip.visible = true;
    pmrem.dispose();
    const keyL = new THREE.DirectionalLight(0xffffff, 1.4); keyL.position.set(3, 5, 6);
    const rimL = new THREE.DirectionalLight(0xff2a44, RIM); rimL.position.set(-5, -4, -3);
    scene.add(keyL, rimL, new THREE.AmbientLight(0xffffff, 0.08));

    const C = { g1: new THREE.Color(0x2a2b30), g2: new THREE.Color(0x4a4b52), bone: new THREE.Color(0xcfd0d6), hot: new THREE.Color(0xff4d62), dim: new THREE.Color(0x161619) };
    const pick = r => (r < 0.012 ? C.hot : r < 0.14 ? C.bone : r < 0.42 ? C.g2 : C.g1);
    const M = {
      chrome: new THREE.MeshPhysicalMaterial({ color: 0xd6d7dd, metalness: 1, roughness: 0.2, clearcoat: 0.4, clearcoatRoughness: 0.18 }),
      gun: new THREE.MeshPhysicalMaterial({ color: 0x34353b, metalness: 1, roughness: 0.28, clearcoat: 0.6, clearcoatRoughness: 0.2 }),
      ink: new THREE.MeshPhysicalMaterial({ color: 0x0a0a0c, metalness: 0.5, roughness: 0.28, clearcoat: 1, clearcoatRoughness: 0.1 }),
      glow: new THREE.MeshBasicMaterial({ color: new THREE.Color(0xc3122b).multiplyScalar(1.15), toneMapped: false }),
      cells: () => new THREE.MeshPhysicalMaterial({ color: 0xffffff, metalness: 0.88, roughness: 0.3, clearcoat: 0.5, clearcoatRoughness: 0.2 }),
    };
    const glowBase = M.glow.color.clone();

    const v3 = new THREE.Vector3(), dummy = new THREE.Object3D(), qI = new THREE.Quaternion();
    const rnd = (a, b) => a + Math.random() * (b - a);
    const unit = () => { const u = rnd(-1, 1), th = rnd(0, Math.PI * 2), s = Math.sqrt(1 - u * u); return new THREE.Vector3(s * Math.cos(th), u, s * Math.sin(th)); };
    const easeOut = x => 1 - Math.pow(1 - x, 3);
    const easeIO = x => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
    const smooth = (a, b, x) => { const q = clamp((x - a) / (b - a), 0, 1); return q * q * (3 - 2 * q); };
    const stepS = (s, dt) => { if (reduced) { s.snap(); return; } const n = Math.ceil(dt / 0.004) || 1; for (let i = 0; i < n; i++) s.step(dt / n); if (s.rest) s.snap(); };

    // ── objects: root (anchor position, size) → spin (idle, parallax, drag) → body (appear, breath)
    const objs = {};
    function base(name, idle) {
      const root = new THREE.Group(), spin = new THREE.Group(), body = new THREE.Group();
      root.add(spin); spin.add(body); scene.add(root); root.visible = false;
      return { name, root, spin, body, idle, samples: new Float32Array(N * 3), tick: null, anchor: null, vis: false,
        a: new Spring(0, 170, 0.8), px: new Spring(0, 300, 0.92), py: new Spring(0, 300, 0.92), ps: new Spring(0, 300, 0.92) };
    }
    function shieldPath(p, sc, dy) {
      const P = (x, y) => [x * sc, y * sc + dy];
      p.moveTo(...P(0, 0.84));
      p.bezierCurveTo(...P(0.28, 0.98), ...P(0.6, 0.96), ...P(0.82, 0.86));
      p.bezierCurveTo(...P(0.86, 0.2), ...P(0.7, -0.5), ...P(0, -1));
      p.bezierCurveTo(...P(-0.7, -0.5), ...P(-0.86, 0.2), ...P(-0.82, 0.86));
      p.bezierCurveTo(...P(-0.6, 0.96), ...P(-0.28, 0.98), ...P(0, 0.84));
      return p;
    }
    function makeShield() {
      const o = base('shield', t => [Math.sin(t * 0.31) * 0.07, Math.sin(t * 0.45) * 0.34, 0]);
      const outer = shieldPath(new THREE.Shape(), 1, 0);
      outer.holes.push(shieldPath(new THREE.Path(), 0.8, 0.04));
      const rimG = new THREE.ExtrudeGeometry(outer, { depth: 0.2, bevelEnabled: true, bevelThickness: 0.07, bevelSize: 0.05, bevelSegments: 5, curveSegments: 48 });
      rimG.translate(0, 0, -0.1);
      const ins = shieldPath(new THREE.Shape(), 0.795, 0.04);
      const kh = new THREE.Path(), cy = 0.14, r = 0.12;
      kh.moveTo(-0.045, cy + r * Math.sin(4.3286));
      kh.absarc(0, cy, r, 4.3286, -1.1864, true);
      kh.lineTo(0.075, -0.3); kh.lineTo(-0.075, -0.3); kh.closePath();
      ins.holes.push(kh);
      const insG = new THREE.ExtrudeGeometry(ins, { depth: 0.1, bevelEnabled: true, bevelThickness: 0.02, bevelSize: 0.015, bevelSegments: 2, curveSegments: 48 });
      insG.translate(0, 0, -0.05);
      const plate = new THREE.Mesh(new THREE.PlaneGeometry(0.3, 0.56), M.glow);
      plate.position.set(0, -0.03, -0.085);
      o.body.add(new THREE.Mesh(rimG, M.chrome), new THREE.Mesh(insG, M.ink), plate);
      const poly = outer.getPoints(96).map(p => [p.x, p.y]);
      const inside = (x, y) => {
        let c = false;
        for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
          const [xi, yi] = poly[i], [xj, yj] = poly[j];
          if ((yi > y) !== (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi) c = !c;
        }
        return c;
      };
      for (let i = 0; i < N; i++) {
        let x, y, z;
        const q = Math.random();
        if (q < 0.2) { const p = poly[(Math.random() * poly.length) | 0]; x = p[0]; y = p[1]; z = rnd(-0.15, 0.15); }
        else { do { x = rnd(-0.86, 0.86); y = rnd(-1, 0.98); } while (!inside(x, y)); z = q < 0.85 ? 0.13 : rnd(-0.15, 0.15); }
        o.samples.set([x, y, z], i * 3);
      }
      return o;
    }
    function makeRings() {
      const o = base('rings', t => [0.5 + Math.sin(t * 0.3) * 0.12, t * 0.42, 0.18]);
      const f = 0.58, R = f, rr = 0.22 * f;
      const g = new THREE.TorusGeometry(R, rr, 40, 140);
      const a = new THREE.Mesh(g, M.chrome); a.position.x = -0.5 * f;
      const b = new THREE.Mesh(g, M.gun); b.position.x = 0.5 * f; b.rotation.x = Math.PI / 2;
      o.body.add(a, b);
      for (let i = 0; i < N; i++) {
        const u = rnd(0, Math.PI * 2), w = rnd(0, Math.PI * 2);
        let x = (R + rr * Math.cos(w)) * Math.cos(u), y = (R + rr * Math.cos(w)) * Math.sin(u), z = rr * Math.sin(w);
        if (i % 2) { const yy = y; y = -z; z = yy; x += 0.5 * f; } else x -= 0.5 * f;
        o.samples.set([x, y, z], i * 3);
      }
      return o;
    }
    function makeAsh() {
      const o = base('ash', t => [0.32, t * 0.14, 0]);
      const n = 460, im = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), M.cells(), n);
      im.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      const home = [], st = [], baseC = [], ga = Math.PI * (3 - Math.sqrt(5)), tmp = new THREE.Color();
      for (let i = 0; i < n; i++) {
        const y = 1 - (i + 0.5) / n * 2, r = Math.sqrt(1 - y * y), th = ga * i;
        const p = new THREE.Vector3(Math.cos(th) * r, y, Math.sin(th) * r).multiplyScalar(0.86);
        home.push(p);
        const c = pick(0.04 + Math.random() * 0.96).clone();
        baseC.push(c); im.setColorAt(i, c);
        st.push({ m: 0, t0: 0, next: rnd(0.4, 14), dur: rnd(1.4, 2.2), s: rnd(0.06, 0.085),
          dir: p.clone().normalize().add(new THREE.Vector3(rnd(-0.3, 0.3), rnd(0.4, 0.9), rnd(-0.3, 0.3))).normalize(),
          rot: new THREE.Euler(rnd(0, 3), rnd(0, 3), rnd(0, 3)) });
      }
      o.body.add(im);
      for (let i = 0; i < N; i++) { const p = home[i % n]; o.samples.set([p.x, p.y, p.z], i * 3); }
      o.tick = t => {
        for (let i = 0; i < n; i++) {
          const s = st[i], p = home[i];
          let sc = s.s, x = p.x, y = p.y, z = p.z;
          if (s.m === 0 && t > s.next && !reduced) { s.m = 1; s.t0 = t; }
          if (s.m === 1) {
            const u = (t - s.t0) / s.dur;
            if (u >= 1) { s.m = 2; s.t0 = t; sc = 0; im.setColorAt(i, baseC[i]); }
            else {
              const d = u * 0.9;
              x += s.dir.x * d + Math.sin(t * 3 + i) * 0.04 * u; y += s.dir.y * d + u * u * 0.5; z += s.dir.z * d;
              sc = s.s * (1 - u);
              tmp.copy(baseC[i]).lerp(C.hot, Math.max(0, 1 - u * 2.2) * 0.9);
              if (u > 0.45) tmp.lerp(C.dim, (u - 0.45) / 0.55);
              im.setColorAt(i, tmp);
            }
          } else if (s.m === 2) {
            const u = (t - s.t0) / 0.7;
            if (u >= 1) { s.m = 0; s.next = t + rnd(5, 16); } else sc = s.s * easeOut(u);
          }
          dummy.position.set(x, y, z); dummy.rotation.copy(s.rot); dummy.scale.setScalar(Math.max(1e-4, sc));
          dummy.updateMatrix(); im.setMatrixAt(i, dummy.matrix);
        }
        im.instanceMatrix.needsUpdate = true;
        if (im.instanceColor) im.instanceColor.needsUpdate = true;
      };
      return o;
    }
    function makeCube() {
      const o = base('cube', t => [0.52, 0.62 + t * 0.3, 0]);
      const n = 64, mat = M.cells();
      mat.metalness = 0.7; mat.envMapIntensity = 0.7; mat.envMap = envCool;
      const im = new THREE.InstancedMesh(new THREE.BoxGeometry(0.36, 0.36, 0.36), mat, n);
      im.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
      const cells = [];
      for (let i = 0; i < n; i++) {
        const gx = i % 4, gy = (i >> 2) % 4, gz = i >> 4;
        cells.push({ home: new THREE.Vector3((gx - 1.5) * 0.42, (gy - 1.5) * 0.42, (gz - 1.5) * 0.42),
          far: unit().multiplyScalar(rnd(1.3, 2.4)),
          q: new THREE.Quaternion().setFromEuler(new THREE.Euler(rnd(-3, 3), rnd(-3, 3), rnd(-3, 3))),
          a: 0, thr: gy / 4 * 0.78 + Math.random() * 0.2 });
        im.setColorAt(i, Math.random() < 0.12 ? C.bone : Math.random() < 0.5 ? C.g2 : C.g1);
      }
      o.body.add(im);
      for (let i = 0; i < N; i++) { const c = cells[i % n].home; o.samples.set([c.x + rnd(-0.17, 0.17), c.y + rnd(-0.17, 0.17), c.z + rnd(-0.17, 0.17)], i * 3); }
      o.p = prog;
      o.tick = (t, dt) => {
        for (let i = 0; i < n; i++) {
          const c = cells[i], target = o.p >= c.thr ? 1 : 0;
          c.a = reduced ? target : clamp(c.a + (target ? dt : -dt) / 0.6, 0, 1);
          const e = easeIO(c.a);
          dummy.position.lerpVectors(c.far, c.home, e);
          dummy.quaternion.slerpQuaternions(c.q, qI, e);
          dummy.scale.setScalar(0.55 + 0.45 * e);
          dummy.updateMatrix(); im.setMatrixAt(i, dummy.matrix);
        }
        im.instanceMatrix.needsUpdate = true;
        mat.emissive.copy(C.bone).multiplyScalar(flash * 0.3);
      };
      return o;
    }
    const MAKE = { shield: makeShield, rings: makeRings, ash: makeAsh, cube: makeCube };
    const get = name => objs[name] || (objs[name] = MAKE[name]());

    // ── swarm: 480 cubes on quadratic bezier arcs ──
    const swarm = new THREE.InstancedMesh(new THREE.BoxGeometry(1, 1, 1), M.cells(), N);
    swarm.instanceMatrix.setUsage(THREE.DynamicDrawUsage);
    swarm.frustumCulled = false; swarm.visible = false;
    const sw = [];
    for (let i = 0; i < N; i++) { sw.push({ d: Math.random() * 0.3, ax: unit(), sp: rnd(2, 7), arc: unit(), k: rnd(0.7, 1.25) }); swarm.setColorAt(i, pick(Math.random())); }
    scene.add(swarm);
    const A = new Float32Array(N * 3), B = new Float32Array(N * 3), P = new Float32Array(N * 3);
    let job = null, cur = null, flash = 0;

    function worldSamples(o, out) {
      place(o, performance.now() / 1000);
      o.root.updateMatrixWorld(true);
      const m = o.spin.matrixWorld;
      for (let i = 0; i < N; i++) v3.fromArray(o.samples, i * 3).applyMatrix4(m).toArray(out, i * 3);
    }
    function startJob(kind, from, to) {
      const s0 = job ? job.s0 : from ? from.ps.x * 0.06 : to.ps.x * 0.06;
      if (job && swarm.visible) A.set(P);
      else if (from) worldSamples(from, A);
      else for (let i = 0; i < N; i++) v3.copy(unit()).multiplyScalar(rnd(2.6, 5) * to.ps.x).add(new THREE.Vector3(to.px.x, to.py.x, 0)).toArray(A, i * 3);
      if (from) { from.a.snap(0); from.root.visible = false; }
      let span = 0.5 * (to ? to.ps.x : from.ps.x);
      if (kind === 'scatter') {
        const cx = from.px.x, cy = from.py.x;
        for (let i = 0; i < N; i++) {
          v3.set(A[i * 3] - cx, A[i * 3 + 1] - cy, A[i * 3 + 2]).normalize().add(unit().multiplyScalar(0.6)).normalize().multiplyScalar(rnd(2, 4.5) * from.ps.x);
          B[i * 3] = A[i * 3] + v3.x; B[i * 3 + 1] = A[i * 3 + 1] + v3.y; B[i * 3 + 2] = A[i * 3 + 2] + v3.z;
        }
        span = 0.4 * from.ps.x;
      } else if (from) span += 0.25 * Math.hypot(to.px.x - from.px.x, to.py.x - from.py.x);
      if (to) to.a.snap(0);
      job = { kind, t0: performance.now(), to, F: kind === 'scatter' ? 0.95 : 0.85, s0, span, shown: false };
      swarm.visible = true;
    }
    function runJob(now) {
      const e = (now - job.t0) / 1000, to = job.to;
      let m = null;
      if (to) { place(to, now / 1000); to.root.updateMatrixWorld(true); m = to.spin.matrixWorld; }
      const s1 = to ? to.ps.x * 0.06 : job.s0;
      let all = true;
      for (let i = 0; i < N; i++) {
        const s = sw[i], u = clamp((e - s.d) / job.F, 0, 1);
        if (u < 1) all = false;
        const w = job.kind === 'scatter' ? easeOut(u) : easeIO(u);
        let bx, by, bz;
        if (m) { v3.fromArray(to.samples, i * 3).applyMatrix4(m); bx = v3.x; by = v3.y; bz = v3.z; }
        else { bx = B[i * 3]; by = B[i * 3 + 1]; bz = B[i * 3 + 2]; }
        const ax = A[i * 3], ay = A[i * 3 + 1], az = A[i * 3 + 2];
        const cx = (ax + bx) / 2 + s.arc.x * job.span, cy = (ay + by) / 2 + s.arc.y * job.span, cz = (az + bz) / 2 + s.arc.z * job.span;
        const k0 = (1 - w) * (1 - w), k1 = 2 * (1 - w) * w, k2 = w * w;
        const x = k0 * ax + k1 * cx + k2 * bx, y = k0 * ay + k1 * cy + k2 * by, z = k0 * az + k1 * cz + k2 * bz;
        P[i * 3] = x; P[i * 3 + 1] = y; P[i * 3 + 2] = z;
        let sc = (job.s0 + (s1 - job.s0) * w) * s.k;
        sc *= job.kind === 'scatter' ? 1 - smooth(0.35, 1, u) : 1 - smooth(0.78, 1, u);
        dummy.position.set(x, y, z);
        dummy.quaternion.setFromAxisAngle(s.ax, e * s.sp);
        dummy.scale.setScalar(Math.max(1e-4, sc));
        dummy.updateMatrix(); swarm.setMatrixAt(i, dummy.matrix);
      }
      swarm.instanceMatrix.needsUpdate = true;
      if (to && !job.shown && e >= 0.55) job.shown = true;
      if (all) { swarm.visible = false; job = null; }
    }

    // ── anchors, parallax, drag ──
    const par = { x: new Spring(0, 60, 0.9), y: new Spring(0, 60, 0.9) }, ptr = { x: 0, y: 0 };
    const drag = { x: new Spring(0, 70, 0.35), y: new Spring(0, 70, 0.35), on: false };
    const hooked = new WeakSet();
    function follow(o, snap) {
      const el = o.anchor;
      let vis = !!(el && el.isConnected && el.offsetParent !== null), r = null;
      if (vis) { r = el.getBoundingClientRect(); vis = r.width > 4 && r.height > 4 && r.bottom > 0 && r.top < H && r.right > 0 && r.left < W; }
      if (vis) {
        o.px.to = (r.left + r.width / 2 - W / 2) * K;
        o.py.to = -(r.top + r.height / 2 - H / 2) * K;
        o.ps.to = Math.min(r.width, r.height) * K * 0.5 * 0.8;
        if (snap) { o.px.snap(); o.py.snap(); o.ps.snap(); }
      }
      o.vis = vis;
    }
    function place(o, t) {
      o.root.position.set(o.px.x, o.py.x, 0);
      o.root.scale.setScalar(Math.max(1e-4, o.ps.x));
      const [ix, iy, iz] = o.idle(reduced ? 1.4 : t);
      o.spin.rotation.set(ix + par.y.x * 0.28 + drag.y.x, iy + par.x.x * 0.45 + drag.x.x, iz);
      const br = reduced ? 1 : 1 + Math.sin(t * 1.3) * 0.012;
      o.body.scale.setScalar(Math.max(1e-4, o.a.x * br * (1 + flash * 0.04)));
      o.root.visible = o.a.x > 0.003;
    }
    function hook(el) {
      if (!el || hooked.has(el)) return;
      hooked.add(el);
      let x0 = 0, y0 = 0, bx = 0, by = 0;
      el.addEventListener('pointerdown', e => {
        if (!el.classList.contains('hit') || reduced) return;
        drag.on = true; x0 = e.clientX; y0 = e.clientY; bx = drag.x.x; by = drag.y.x;
        el.setPointerCapture(e.pointerId); el.style.cursor = 'grabbing'; wake();
      });
      el.addEventListener('pointermove', e => {
        if (!drag.on) return;
        drag.x.snap(bx + (e.clientX - x0) * 0.012);
        drag.y.snap(clamp(by + (e.clientY - y0) * 0.008, -0.6, 0.6));
      });
      const up = () => { if (!drag.on) return; drag.on = false; drag.x.to = 0; drag.y.to = 0; el.style.cursor = ''; };
      el.addEventListener('pointerup', up);
      el.addEventListener('pointercancel', up);
    }
    addEventListener('pointermove', e => {
      if (e.pointerType !== 'mouse') return;
      ptr.x = clamp(e.clientX / W * 2 - 1, -1, 1); ptr.y = clamp(e.clientY / H * 2 - 1, -1, 1);
    }, { passive: true });

    // ── particles: ~700 additive points, rain as lines ──
    const pf = (() => {
      const n = LITE ? 380 : 700;
      const pos = new Float32Array(n * 3), vel = new Float32Array(n * 3), seed = new Float32Array(n), size = new Float32Array(n);
      const g = new THREE.BufferGeometry();
      const pa = new THREE.BufferAttribute(pos, 3); pa.setUsage(THREE.DynamicDrawUsage);
      g.setAttribute('position', pa);
      g.setAttribute('aSeed', new THREE.BufferAttribute(seed, 1));
      const sa = new THREE.BufferAttribute(size, 1); g.setAttribute('aSize', sa);
      const mat = new THREE.ShaderMaterial({
        uniforms: { uColor: { value: new THREE.Color() }, uPR: { value: 1 }, uAlpha: { value: 0.5 }, uTime: { value: 0 }, uTw: { value: 0.35 } },
        vertexShader: 'attribute float aSize;attribute float aSeed;uniform float uPR;varying float vSeed;void main(){vec4 mv=modelViewMatrix*vec4(position,1.);gl_Position=projectionMatrix*mv;gl_PointSize=aSize*uPR*(10./max(.5,-mv.z));vSeed=aSeed;}',
        fragmentShader: 'uniform vec3 uColor;uniform float uAlpha;uniform float uTime;uniform float uTw;varying float vSeed;void main(){vec2 c=gl_PointCoord-.5;float d=length(c);if(d>.5)discard;float a=smoothstep(.5,0.,d);float tw=1.-uTw+uTw*sin(uTime*2.2+vSeed*40.);gl_FragColor=vec4(uColor*a*uAlpha*tw,0.);}',
        transparent: true, premultipliedAlpha: true, depthWrite: false, blending: THREE.AdditiveBlending,
      });
      const points = new THREE.Points(g, mat);
      points.frustumCulled = false; points.renderOrder = -1; points.visible = false;
      const lpos = new Float32Array(n * 6);
      const lg = new THREE.BufferGeometry();
      const la = new THREE.BufferAttribute(lpos, 3); la.setUsage(THREE.DynamicDrawUsage);
      lg.setAttribute('position', la);
      const lines = new THREE.LineSegments(lg, new THREE.LineBasicMaterial({ color: 0xc8c9d0, transparent: true, opacity: 0.16, blending: THREE.AdditiveBlending, depthWrite: false }));
      lines.frustumCulled = false; lines.renderOrder = -1; lines.visible = false;
      scene.add(points, lines);
      const Z0 = -6, Z1 = 3;
      let mode = 'none', hw = 6, hh = 4;
      const CONF = {
        dust: { c: [0.5, 0.51, 0.56], a: 0.55, s: [3, 6], tw: 0.35 },
        snow: { c: [0.8, 0.81, 0.86], a: 0.5, s: [4, 8], tw: 0.1 },
        embers: { c: [1, 0.26, 0.32], a: 0.75, s: [3, 6.5], tw: 0.55 },
        orbit: { c: [0.7, 0.71, 0.77], a: 0.5, s: [2.5, 5], tw: 0.25 },
      };
      function bounds() { hh = Math.tan(FOV * Math.PI / 360) * (CZ - Z0) * 1.05; hw = hh * camera.aspect; }
      function spawn(i, first) {
        const x = rnd(-hw, hw), z = rnd(Z0, Z1);
        let y = rnd(-hh, hh);
        if (mode === 'snow' && !first) y = hh + rnd(0, 1);
        if (mode === 'embers' && !first) y = -hh - rnd(0, 1);
        pos[i * 3] = x; pos[i * 3 + 1] = y; pos[i * 3 + 2] = z;
        if (mode === 'dust') { vel[i * 3] = rnd(-0.06, 0.06); vel[i * 3 + 1] = rnd(-0.04, 0.05); vel[i * 3 + 2] = rnd(-0.03, 0.03); }
        if (mode === 'snow') { vel[i * 3] = 0; vel[i * 3 + 1] = -rnd(0.18, 0.5); vel[i * 3 + 2] = 0; }
        if (mode === 'embers') { vel[i * 3] = rnd(-0.05, 0.05); vel[i * 3 + 1] = rnd(0.25, 0.8); vel[i * 3 + 2] = 0; }
        if (mode === 'orbit') { vel[i * 3] = rnd(1.8, Math.max(2.4, hw * 0.95)); vel[i * 3 + 1] = rnd(0, Math.PI * 2); vel[i * 3 + 2] = rnd(0.04, 0.12) * (Math.random() < 0.5 ? 1 : -1) / Math.sqrt(vel[i * 3] / 2); }
        if (mode === 'rain') { vel[i * 3] = -rnd(5, 9); vel[i * 3 + 1] = rnd(0.25, 0.6); if (!first) pos[i * 3 + 1] = hh + rnd(0, 2); }
      }
      function set(m) {
        mode = CONF[m] || m === 'rain' ? m : 'none';
        points.visible = !!CONF[mode]; lines.visible = mode === 'rain';
        if (CONF[mode]) {
          const c = CONF[mode];
          mat.uniforms.uColor.value.setRGB(c.c[0], c.c[1], c.c[2]);
          mat.uniforms.uAlpha.value = c.a; mat.uniforms.uTw.value = c.tw;
          for (let i = 0; i < n; i++) { seed[i] = Math.random(); size[i] = rnd(c.s[0], c.s[1]); }
          g.attributes.aSeed.needsUpdate = true; sa.needsUpdate = true;
        }
        for (let i = 0; i < n; i++) spawn(i, true);
        tick(0, 0);
      }
      function tick(t, dt) {
        mat.uniforms.uTime.value = t;
        mat.uniforms.uPR.value = renderer.getPixelRatio();
        if (mode === 'none') return;
        if (mode === 'rain') {
          for (let i = 0; i < n; i++) {
            const vy = vel[i * 3], L = vel[i * 3 + 1];
            pos[i * 3 + 1] += vy * dt; pos[i * 3] += vy * 0.12 * dt;
            if (pos[i * 3 + 1] < -hh - 1) spawn(i, false);
            const x = pos[i * 3], y = pos[i * 3 + 1], z = pos[i * 3 + 2], k = L / Math.hypot(1, 0.12);
            lpos.set([x, y, z, x + 0.12 * k, y + k, z], i * 6);
          }
          la.needsUpdate = true;
          return;
        }
        for (let i = 0; i < n; i++) {
          if (mode === 'orbit') {
            const r = vel[i * 3]; vel[i * 3 + 1] += vel[i * 3 + 2] * dt;
            const a = vel[i * 3 + 1];
            pos[i * 3] = Math.cos(a) * r; pos[i * 3 + 1] = Math.sin(a) * r * 0.32 + (seed[i] - 0.5) * 0.5; pos[i * 3 + 2] = Math.sin(a) * r * 0.9 - 2;
            continue;
          }
          pos[i * 3] += (vel[i * 3] + (mode === 'snow' ? Math.sin(t * 0.8 + seed[i] * 30) * 0.12 : 0)) * dt;
          pos[i * 3 + 1] += vel[i * 3 + 1] * dt;
          pos[i * 3 + 2] += vel[i * 3 + 2] * dt;
          const y = pos[i * 3 + 1], x = pos[i * 3];
          if (mode === 'snow' && y < -hh - 0.5) spawn(i, false);
          else if (mode === 'embers' && y > hh + 0.5) spawn(i, false);
          else if (mode === 'dust') {
            if (x > hw) pos[i * 3] -= 2 * hw; if (x < -hw) pos[i * 3] += 2 * hw;
            if (y > hh) pos[i * 3 + 1] -= 2 * hh; if (y < -hh) pos[i * 3 + 1] += 2 * hh;
          }
        }
        pa.needsUpdate = true;
      }
      return { set, tick, bounds, get mode() { return mode; } };
    })();

    // ── loop: sleeps when nothing moves ──
    let running = false, last = 0, hold = 0, covered = false, coverT = 0;
    function uncover() {
      clearTimeout(coverT);
      if (covered) { covered = false; canvas.style.visibility = ''; }
    }
    function wake() {
      hold = performance.now() + 450;
      if (running || covered) return;
      running = true; last = performance.now();
      requestAnimationFrame(frame);
    }
    function frame(now) {
      if (document.hidden || covered) { running = false; return; }
      const dt = Math.min(0.05, Math.max(0, (now - last) / 1000)), t = now / 1000;
      last = now;
      stepS(par.x, dt); stepS(par.y, dt);
      par.x.to = ptr.x; par.y.to = ptr.y;
      if (!drag.on) { stepS(drag.x, dt); stepS(drag.y, dt); }
      flash *= Math.exp(-dt * 3.2);
      M.glow.color.copy(glowBase).multiplyScalar(1 + flash * 2.4);
      // flat metal faces mirror the red rim whole; the cube keeps it as a thin edge only
      { const rt = cur && cur.name === 'cube' ? 0.2 : RIM; rimL.intensity = reduced ? rt : rimL.intensity + (rt - rimL.intensity) * Math.min(1, dt * 6); }
      if (cur) follow(cur, false);
      for (const k in objs) {
        const o = objs[k];
        o.a.to = o === cur && o.vis && (!job || job.to !== o || job.shown) ? 1 : 0;
        stepS(o.a, dt); stepS(o.px, dt); stepS(o.py, dt); stepS(o.ps, dt);
        place(o, t);
        if (o.root.visible && o.tick) o.tick(t, dt);
      }
      if (job) runJob(now);
      if (!reduced) pf.tick(t, dt);
      renderer.render(scene, camera);
      const busy = now < hold || (!reduced && (cur || job || pf.mode !== 'none' || drag.on || Object.values(objs).some(o => o.root.visible)));
      if (busy) requestAnimationFrame(frame); else running = false;
    }
    function resize() {
      W = innerWidth; H = innerHeight;
      renderer.setPixelRatio(Math.min(devicePixelRatio || 1, LITE ? 1.25 : 1.5));
      renderer.setSize(W, H, false);
      camera.aspect = W / Math.max(1, H);
      camera.updateProjectionMatrix();
      K = 2 * Math.tan(FOV * Math.PI / 360) * CZ / Math.max(1, H);
      pf.bounds();
      wake();
    }
    addEventListener('resize', resize);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) wake(); });
    motionSubs.add(() => { pf.set(pf.mode); wake(); });
    canvas.addEventListener('webglcontextlost', e => { e.preventDefault(); running = false; });
    canvas.addEventListener('webglcontextrestored', () => wake());
    resize();

    return {
      show(name, anchor, o = {}) {
        uncover();
        if (anchor) { anchor.classList.remove('flat'); hook(anchor); }
        if (!name || !MAKE[name]) { cur = null; wake(); return; }
        const next = get(name);
        next.anchor = anchor;
        if (cur === next) { wake(); return; }
        follow(next, true);
        if (!reduced && cur && o.morph && cur.vis && cur.a.x > 0.4) startJob('morph', cur, next);
        else if (!reduced && o.assemble && next.vis) startJob('assemble', null, next);
        cur = next;
        wake();
      },
      scatter() {
        if (!cur) return;
        if (!reduced && cur.vis && cur.a.x > 0.4) startJob('scatter', cur, null);
        cur = null;
        wake();
      },
      rest(ms) {
        clearTimeout(coverT);
        coverT = setTimeout(() => { covered = true; canvas.style.visibility = 'hidden'; }, ms);
      },
      particles(m) { pf.set(m); wake(); },
      progress(p) { if (objs.cube) objs.cube.p = p; wake(); },
      pulse() { flash = reduced ? 0 : 1; wake(); },
      snapshot() {
        try { renderer.render(scene, camera); return canvas.toDataURL('image/png'); } catch (e) { return null; }
      },
    };
  }
})();

// entry.js
'use strict';
/* Entry: splash, onboarding, auth, gate, PIN setup, lock.
   One "wow" per screen: splash = shield assembles, onb = object morph, auth = the card turns over,
   gate = the shield folds into the cube (creating or signing in), PIN = dots, lock = the lid closes. */

// ── shared helpers ───────────────────────────────────────
function enTimers() {
  const ids = new Set();
  return {
    after(ms, f) { const id = setTimeout(() => { ids.delete(id); f(); }, reduced ? 0 : ms); ids.add(id); return id; },
    clear() { ids.forEach(clearTimeout); ids.clear(); },
  };
}
function enLayout(cls, obj, kids) {
  return h('div.e' + cls, h('div.art', obj), h('div.pane', h('div.col', kids)));
}
function enLid(el) {
  if (reduced || !el) return Promise.resolve();
  const line = h('div.lidline', { 'aria-hidden': 'true' });
  ENTRY.append(line);
  anim(line, [{ transform: 'scaleX(0)', opacity: 0 }, { transform: 'scaleX(1)', opacity: 1, offset: 0.7 }, { transform: 'scaleX(1)', opacity: 0 }],
    { duration: 1200, easing: E.soft }).then(() => line.remove());
  return anim(el, [{ transform: 'none', filter: 'brightness(1)' }, { transform: 'scaleY(.004)', filter: 'brightness(2.2)' }],
    { duration: 900, easing: E.soft, fill: 'forwards' });
}
function enPinDots(n) {
  const el = h('div.pin', { 'aria-hidden': 'true' });
  el.size = k => { n = k; el.replaceChildren(...Array.from({ length: n }, () => h('i'))); };
  el.fill = k => [...el.children].forEach((d, i) => d.classList.toggle('on', i < k));
  el.state = s => { el.classList.remove('err', 'ok'); if (s) el.classList.add(s); if (s === 'err') shake(el); };
  el.size(n);
  return el;
}
/* Keypad: digits, a function key on the left, backspace on the right. */
function enKeypad(onKey, fn) {
  const key = (v, label) => h('button.key', { type: 'button', 'data-k': v, 'aria-label': label || null }, v);
  const pad = h('div.keypad', [1, 2, 3, 4, 5, 6, 7, 8, 9].map(d => key(String(d))),
    fn ? h('button.key.fn', { type: 'button', 'data-k': 'fn' }, fn) : h('span'),
    key('0'),
    h('button.key.fn', { type: 'button', 'data-k': 'del', 'aria-label': t('d.erase') }, ico('backspace')));
  pad.addEventListener('click', e => { const b = e.target.closest('button'); if (b) onKey(b.dataset.k); });
  const kb = e => {
    if ((e.target.closest && e.target.closest('input, textarea')) || e.ctrlKey || e.metaKey || e.altKey) return;
    if (/^[0-9]$/.test(e.key)) { onKey(e.key); enPress(pad, e.key); }
    else if (e.key === 'Backspace') { onKey('del'); enPress(pad, 'del'); }
  };
  pad.listen = () => document.addEventListener('keydown', kb);
  pad.unlisten = () => document.removeEventListener('keydown', kb);
  return pad;
}
function enPress(pad, k) {
  const b = pad.querySelector(`[data-k="${k}"]`);
  if (b) anim(b, [{ transform: 'scale(.9)' }, { transform: 'none' }], { duration: 220, easing: E.out });
}
const enErr = e => (e && e.key) || 'err.network';

// ── splash ───────────────────────────────────────────────
function scrSplash() {
  const T = enTimers();
  const obj = h('div.obj3d');
  const word = h('div.sp-word', { role: 'img', 'aria-label': 'Aegis' }, [...'AEGIS'].map(c => h('span', { 'aria-hidden': 'true' }, c)));
  const bar = h('i');
  const a = h('span'), b = h('b');
  const line = h('p.sp-line.t-hud', a, ' ', b);
  const el = h('div.splash', { role: 'button', tabindex: '0', 'aria-label': t('guide.next') }, obj, word, h('div.sp-bar', { 'aria-hidden': 'true' }, bar), line);
  let left = false;
  const leave = () => {
    if (left) return;
    left = true;
    go(ENV.tab === 'unlock' ? authScr() : 'onb', { tr: 'zoom' });
  };
  el.addEventListener('click', leave);
  el.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); leave(); } });
  el._enter = () => {
    AegisScene.show('shield', obj, { assemble: true });
    [...word.children].forEach((s, i) => anim(s,
      [{ transform: 'translateY(.35em) rotateX(-80deg)', opacity: 0 }, { transform: 'none', opacity: 1 }],
      { duration: 760, delay: 260 + i * 70, easing: E.back, fill: 'backwards' }));
    anim(bar, [{ transform: 'scaleX(0)' }, { transform: 'scaleX(1)' }], { duration: 1700, delay: 300, easing: E.soft, fill: 'forwards' });
    T.after(500, () => decode(a, t('d.splash_a'), 800).then(() => decode(b, t('d.splash_b'), 800)));
    T.after(3200, leave);
  };
  el._off = () => T.clear();
  return el;
}

// ── onboarding: 3 slides, the object morphs shield → rings → ash ──
function scrOnb() {
  const OBJ = ['shield', 'rings', 'ash'];
  const DATA = [['d.onb1', 'auth.pwnote'], ['d.onb2', 'contact.safety_note'], ['d.onb3', 'conn.cover_note']];
  const obj = h('div.obj3d');
  const slides = h('div.onb-slides', DATA.map(([a, b], i) => h('article', { 'aria-roledescription': 'slide', 'aria-label': `${i + 1} / 3` },
    h('p.onb-n.t-hud', h('b', pad(i + 1)), ' / 03'),
    h('h1.e-title', t(a)),
    h('p.e-sub', t(b)))));
  const track = h('div.onb-track', slides);
  const dots = h('div.dots', { 'aria-hidden': 'true' }, DATA.map(() => h('i')));
  const next = h('button.btn', { type: 'button', 'data-autofocus': '' });
  const skip = h('button.btn.ghost.sm', { type: 'button' }, t('guide.skip'));
  const el = enLayout('.onb', obj, [
    h('div.e-top', h('span.e-word', 'Aegis'), skip),
    track,
    h('div.onb-foot', dots, next),
  ]);
  let i = -1;
  const set = k => {
    k = clamp(k, 0, 2);
    if (k === i) return;
    const first = i < 0;
    i = k;
    slides.style.transform = `translateX(${-i * 100 / 3}%)`;
    [...slides.children].forEach((s, j) => { s.inert = j !== i; });
    [...dots.children].forEach((d, j) => d.classList.toggle('on', j === i));
    next.textContent = i === 2 ? t('d.start') : t('guide.next');
    if (!first) { AegisScene.show(OBJ[i], obj, { morph: true }); announce(t(DATA[i][0])); }
  };
  const done = () => go('auth', { tr: 'push', tab: 'create' });
  next.addEventListener('click', () => (i === 2 ? done() : set(i + 1)));
  skip.addEventListener('click', done);
  // swipe
  let x0 = null;
  track.addEventListener('pointerdown', e => { x0 = e.clientX; });
  track.addEventListener('pointerup', e => {
    if (x0 == null) return;
    const dx = e.clientX - x0; x0 = null;
    if (Math.abs(dx) > 40) set(i + (dx < 0 ? 1 : -1));
  });
  const kb = e => {
    if (e.key === 'ArrowRight') set(i + 1);
    else if (e.key === 'ArrowLeft') set(i - 1);
  };
  set(0);
  el._enter = () => { AegisScene.show(OBJ[0], obj, { morph: true }); document.addEventListener('keydown', kb); };
  el._off = () => document.removeEventListener('keydown', kb);
  return el;
}

// ── auth: one card, three faces. All faces share one grid cell, so the card is as tall
//    as the tallest face (create) and keeps its size when it turns over. ──
const enFlip = springCurve(90, 0.74);
function scrAuth(o = {}) {
  const obj = h('div.obj3d');
  const copy = h('div.au-copy',
    h('span.eyebrow', t('auth.eyebrow')),
    h('h1', t('auth.headline')),
    h('p', t('auth.tagline')),
    h('div.au-chips', ['auth.chip1', 'auth.chip2', 'auth.chip3'].map(k => h('span', t(k)))),
    h('span.au-foot.t-small', t('auth.foot')));
  const TABS = ['unlock', 'create', 'import'];
  const ids = Object.fromEntries(TABS.map(v => [v, uid('au')]));
  const tabs = h('div.seg.tabs', { role: 'tablist' },
    TABS.map(v => h('button', { type: 'button', 'data-v': v, id: ids[v] + 't', 'aria-controls': ids[v] }, t({ unlock: 'auth.tab_unlock', create: 'auth.tab_create', import: 'auth.tab_import' }[v]))));

  const F = {
    // as in 0.2.5: usernames in mono, and the unlock field takes the password or the PIN
    unlock: { user: field({ label: t('f.username'), auto: 'username', name: 'username', mono: true }), pass: field({ label: t('f.secret'), type: 'password', auto: 'current-password' }) },
    create: {
      user: field({ label: t('f.username_new'), auto: 'username', hardMax: 24, mono: true }),
      display: field({ label: t('f.display'), max: 64 }),
      pass: field({ label: t('f.password_new'), type: 'password', auto: 'new-password' }),
      confirm: field({ label: t('f.confirm'), type: 'password', auto: 'new-password' }),
    },
    import: { path: field({ label: t('f.vault_path'), mono: true }), pass: field({ label: t('f.password'), type: 'password', auto: 'current-password' }) },
  };
  // above the button on every face: the password note (0.2.5 shows it under all three tabs),
  // replaced in the same place by the first field error or the progress (the card does not grow)
  const slot = () => {
    const msg = h('p.au-msg', { 'aria-hidden': 'true' });
    const box = h('div.au-say', h('p.au-note', t('auth.pwnote')), msg);
    box.msg = msg;
    return box;
  };
  const say = { unlock: slot(), create: slot(), import: slot() };
  const sync = v => {
    const bad = Object.values(F[v]).find(b => b.wrap.classList.contains('err'));
    if (bad) say[v].msg.textContent = bad.msg.textContent;
    say[v].classList.toggle('bad', !!bad);
  };
  const submit = label => h('button.btn.wide.au-go', { type: 'submit' }, label);
  const face = (v, kids) => h('form.au-face', { id: ids[v], role: 'tabpanel', 'aria-labelledby': ids[v] + 't', novalidate: true }, kids);
  const forms = {
    unlock: face('unlock', [F.unlock.user, F.unlock.pass, say.unlock, submit(t('auth.unlock'))]),
    create: face('create', [F.create.user, F.create.display, F.create.pass, F.create.confirm, say.create, submit(t('auth.create'))]),
    import: face('import', [F.import.path, F.import.pass, h('p.au-hint', t('auth.import_note')), say.import, submit(t('auth.import'))]),
  };
  TABS.forEach(v => forms[v].addEventListener('input', () => sync(v)));

  // the turn: the card sinks a little, rotates half a turn on a spring and comes back up;
  // the leaving face goes into shade, the arriving one comes out of it
  const card = h('div.au-card', h('div.au-flip', TABS.map(v => forms[v])));
  const flipper = card.firstChild;
  let cur = o.tab || (ENV.tab === 'unlock' ? 'unlock' : 'create');
  let rot = 0, turning = [];
  const show = (v, on) => { forms[v].style.visibility = on ? '' : 'hidden'; forms[v].inert = !on; };
  TABS.forEach(v => show(v, v === cur));
  const flip = to => {
    turning.forEach(a => a.finish());
    const from = cur, dir = TABS.indexOf(to) > TABS.indexOf(from) ? 1 : -1;
    const r0 = rot, r1 = rot + 180 * dir;
    cur = to; rot = r1;
    TABS.forEach(v => { if (v !== from && v !== to) show(v, false); });
    forms[to].style.transform = `rotateY(${-r1}deg)`;
    show(to, true);
    flipper.style.transform = `rotateY(${r1}deg)`;
    const opt = { duration: reduced ? 1 : enFlip.duration, easing: enFlip.easing };
    const a = flipper.animate([
      { transform: `translateZ(0) rotateY(${r0}deg)` },
      { transform: `translateZ(-120px) rotateY(${r0 + 90 * dir}deg)`, offset: 0.42 },
      { transform: `translateZ(0) rotateY(${r1}deg)` }], opt);
    turning = [a,
      forms[from].animate([{ filter: 'brightness(1)' }, { filter: 'brightness(.3)', offset: 0.42 }, { filter: 'brightness(.3)' }], opt),
      forms[to].animate([{ filter: 'brightness(.3)' }, { filter: 'brightness(.3)', offset: 0.42 }, { filter: 'brightness(1)' }], opt)];
    card.classList.remove('turning'); void card.offsetWidth; card.classList.add('turning');
    a.finished.catch(() => {}).then(() => {
      if (turning[0] !== a) return;
      turning = [];
      show(from, false);
      card.classList.remove('turning');
      if (isDesk()) forms[to].querySelector('input').focus({ preventScroll: true });
    });
  };
  seg(tabs, cur, flip);

  const run = (v, cmd, args, f) => {
    const btn = forms[v].querySelector('.au-go');
    busy(btn, true);
    ENV.wait = { fail(text) { busy(btn, false); f.error(text); sync(v); }, user: args.username || '' };
    send(cmd, args);
  };
  forms.unlock.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.unlock;
    if (!f.user.input.value.trim()) { f.user.error(t('err.username')); return sync('unlock'); }
    if (!f.pass.input.value) { f.pass.error(t('err.password')); return sync('unlock'); }
    run('unlock', 'unlock', { username: f.user.input.value.trim(), password: f.pass.input.value }, f.pass);
    f.pass.input.value = '';
  });
  // create: the engine checks the fields, then makes the keys and solves the puzzle on the gate
  forms.create.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.create;
    const u = f.user.input.value.trim(), d = f.display.input.value.trim();
    if (!u) { f.user.error(t('err.username')); return sync('create'); }
    if (!f.pass.input.value) { f.pass.error(t('err.password')); return sync('create'); }
    send('create', { username: u, display: d, password: f.pass.input.value, confirm: f.confirm.input.value });
    f.pass.input.value = ''; f.confirm.input.value = '';
    go('gate', { u, d, tr: 'push' });
  });
  forms.import.addEventListener('submit', e => {
    e.preventDefault();
    const f = F.import;
    if (!f.path.input.value.trim()) { f.path.error(t('err.path')); return sync('import'); }
    run('import', 'import', { path: f.path.input.value.trim(), password: f.pass.input.value }, f.pass);
    f.pass.input.value = '';
  });
  ENV.cur = () => cur;

  // the language, as on the 0.2.5 sign-in screen; the screen is rebuilt in the new one
  const lang = h('div.seg.mono.au-lang', { 'aria-label': t('set.language') },
    ['ru', 'en'].map(v => h('button', { type: 'button', 'data-v': v }, v.toUpperCase())));
  seg(lang, LANG, v => {
    LANG = v; send('set_lang', { lang: v }); document.documentElement.lang = v;
    setTimeout(() => go('auth', { tr: 'none', tab: cur }), reduced ? 0 : 280);
  });

  const el = h('div.e.auth', { style: { '--art-h': '26vh' } }, lang,
    h('div.art', obj, copy),
    h('div.pane', h('div.col',
      h('div.au-mobile-head', h('span.eyebrow', t('auth.eyebrow')), h('h1', t('auth.headline'))),
      tabs, card)));
  // back from the gate with what was typed (the passwords are not kept)
  if (o.user) F.unlock.user.input.value = o.user;
  if (o.keep) { F.create.user.input.value = o.keep.u; F.create.display.input.value = o.keep.d; F.create.display.count(); }
  if (o.errorText && F[cur]) { const k = Object.keys(F[cur])[0]; setTimeout(() => { F[cur][k].error(o.errorText); sync(cur); }, 400); }
  el._enter = () => {
    AegisScene.show('shield', obj, { morph: true });
    if (isDesk()) setTimeout(() => forms[cur].querySelector('input').focus({ preventScroll: true }), reduced ? 0 : 450);
  };
  return el;
}

// ── lock: the app was open and locked (idle, minimized, screen off) with a PIN set. The
//    account is known, so only the keypad is shown; the password opens the usual form. ──
function scrLock(o) {
  const L = ENV.lock || {};
  const obj = h('div.obj3d');
  const fixed = L.digits === 4 || L.digits === 6;
  const dots = enPinDots(fixed ? L.digits : 4);
  const msg = h('p.lk-msg', { role: 'status' });
  let pin = '', waiting = false;
  const draw = () => {
    if (!fixed) dots.size(pin.length > 4 ? 6 : 4);
    dots.fill(pin.length);
  };
  const submit = () => {
    if (waiting || !/^(\d{4}|\d{6})$/.test(pin)) return;
    waiting = true;
    ENV.wait = {
      user: L.user,
      fail(text) {
        waiting = false; pin = '';
        dots.state('err'); msg.textContent = text;
        setTimeout(() => { dots.state(null); draw(); }, 600);
      },
    };
    send('unlock', { username: L.user, password: pin });
  };
  const pad = enKeypad(k => {
    if (waiting) return;
    if (k === 'del') pin = pin.slice(0, -1);
    else if (k === 'fn') return submit();
    else if (pin.length < 6) pin += k;
    if (msg.textContent && k !== 'del') msg.textContent = '';
    draw();
    if (fixed && pin.length === L.digits) submit();
  }, fixed ? null : t('d.lock_ok'));
  const pw = h('button.btn.ghost.sm', { type: 'button' }, t('d.use_password'));
  pw.addEventListener('click', () => go('auth', { tr: 'push', tab: 'unlock', user: L.user }));
  const el = enLayout('.lock', obj, [
    h('div.e-top', h('span.e-word', 'Aegis'), pw),
    h('div.pinbox',
      h('b.mono.lk-user', '@' + (L.user || '')),
      h('h1.e-title', t('d.lock_title')),
      dots, msg, pad),
  ]);
  el._enter = () => { AegisScene.show('shield', obj, { morph: true }); pad.listen(); };
  el._off = () => pad.unlisten();
  return el;
}

// ── gate: between the form and the app. The shield folds into the cube and the cube is
//    built from the real work: the keys, then the registration puzzle (create), or a short
//    settle after the vault opened (sign-in, import). No cancel, as in 0.2.5. ──
function scrGate(o) {
  const T = enTimers();
  const obj = h('div.obj3d');
  const making = !o.acct;
  const head = making ? t('d.gate_create') : t('d.gate_open');
  const title = h('h1.e-title', head);
  const who = h('div.gt-who', h('div.gt-id',
    h('b.mono', '@' + (making ? o.u : o.acct.username)), making && o.d ? h('span', o.d) : null));
  const fill = h('i');
  const bar = h('div.gt-bar.wait', { role: 'progressbar', 'aria-label': head }, fill);
  const step = h('span', t('busy.create'));
  let off = false;
  const done = (text, next) => {
    AegisScene.progress(1);
    AegisScene.pulse();
    decode(title, text);
    announce(text);
    T.after(1400, next);
  };
  // creating: the engine makes the keys and solves the puzzle; the cube builds while it works
  const create = () => {
    announce(t('busy.create'));
    const t0 = performance.now();
    const tick = now => {
      if (off) return;
      AegisScene.progress(0.9 * (1 - Math.exp(-(now - t0) / 9000)));
      requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
    ENV.wait = {
      fail(text) { if (!off) go('auth', { tr: 'back', tab: 'create', errorText: text, keep: { u: o.u, d: o.d } }); },
      ok() { off = true; done(t('d.gate_done'), ENV.leave); },
    };
  };
  const open = () => {
    if (reduced) { AegisScene.progress(1); T.after(0, ENV.leave); return; }
    T.after(380, () => {
      const t0 = performance.now(), dur = 820;
      const tick = now => {
        if (off) return;
        const k = Math.min(1, (now - t0) / dur);
        AegisScene.progress(k < 0.5 ? 2 * k * k : 1 - (-2 * k + 2) ** 2 / 2);
        if (k < 1) requestAnimationFrame(tick);
        else T.after(420, () => { AegisScene.pulse(); T.after(460, ENV.leave); });
      };
      requestAnimationFrame(tick);
    });
  };

  const el = enLayout('.gate', obj, [
    h('div.e-top', h('span.e-word', 'Aegis')),
    title, who,
    making && [bar, h('div.gt-line', step)],
  ]);
  el._enter = () => {
    AegisScene.show('cube', obj, { morph: true });
    AegisScene.progress(0);
    if (making) create(); else open();
  };
  el._off = () => { off = true; T.clear(); };
  return el;
}


// crypto.js
// crypto helpers (from the prototype core)

// ── crypto: real keys and hashes, nothing pretends ───────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);
const W256 = new Uint32Array(64);
function sha256(bytes) {
  const l = bytes.length, nb = ((l + 9 + 63) >> 6) << 6;
  const m = new Uint8Array(nb);
  m.set(bytes); m[l] = 0x80;
  const dv = new DataView(m.buffer), bits = l * 8;
  dv.setUint32(nb - 4, bits >>> 0); dv.setUint32(nb - 8, Math.floor(bits / 4294967296));
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a, h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const W = W256;
  for (let o = 0; o < nb; o += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
    for (let i = 16; i < 64; i++) {
      const a = W[i - 15], b = W[i - 2];
      W[i] = (W[i - 16] + ((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) + W[i - 7] + ((b >>> 17 | b << 15) ^ (b >>> 19 | b << 13) ^ (b >>> 10))) | 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let i = 0; i < 64; i++) {
      const t1 = (hh + ((e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) | 0;
      const t2 = (((a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      hh = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    h0 = (h0 + a) | 0; h1 = (h1 + b) | 0; h2 = (h2 + c) | 0; h3 = (h3 + d) | 0; h4 = (h4 + e) | 0; h5 = (h5 + f) | 0; h6 = (h6 + g) | 0; h7 = (h7 + hh) | 0;
  }
  const out = new Uint8Array(32), od = new DataView(out.buffer);
  [h0, h1, h2, h3, h4, h5, h6, h7].forEach((v, i) => od.setUint32(i * 4, v >>> 0));
  return out;
}
const enc = new TextEncoder();
const cat = (...a) => { const n = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const hex = b => [...b].map(x => x.toString(16).padStart(2, '0')).join('');
const rand = n => crypto.getRandomValues(new Uint8Array(n));
/* fingerprint as in the app: hex of the X25519 key, groups of 4, first 8 */
function cmpBytes(a, b) { for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i]; return a.length - b.length; }
const fingerprint = x => hex(x).match(/.{4}/g).slice(0, 8);
/* safety number as in identity.rs: 6 groups of 5 digits */
function safetyNumber(a, b) {
  const [lo, hi] = cmpBytes(a, b) <= 0 ? [a, b] : [b, a];
  const d = sha256(cat(enc.encode('aegis-v2 safety'), lo, hi));
  const g = [];
  for (let i = 0; i < 6; i++) { let v = 0; for (let j = 0; j < 5; j++) v = v * 256 + d[i * 5 + j]; g.push(String(v % 100000).padStart(5, '0')); }
  return g;
}
/* identicon as in avatar.rs: 5x5 mirrored grid, greys from the hash. Drawn like render.rs,
   the cells as one path; only the cells snap to pixels, so the round ground stays smooth */
function identicon(ed) {
  const hsh = sha256(cat(enc.encode('aegis-v2 avatar'), ed));
  const bg = 0x1c + (hsh[2] % 0x18), fg = 0xa0 + (hsh[3] % 0x50);
  const g = v => '#' + v.toString(16).padStart(2, '0').repeat(3);
  let d = '';
  for (let r = 0; r < 5; r++) for (let c = 0; c < 3; c++) {
    const k = r * 3 + c;
    if ((hsh[k >> 3] >> (k % 8)) & 1) {
      d += `M${c + 1} ${r + 1}h1v1h-1z`;
      if (c !== 2) d += `M${5 - c} ${r + 1}h1v1h-1z`;
    }
  }
  return `<svg viewBox="0 0 7 7" class="kg" aria-hidden="true"><rect class="avb" width="7" height="7" rx="3.5" fill="${g(bg)}"/><path fill="${g(fg)}" shape-rendering="crispEdges" d="${d}"/></svg>`;
}

// shell.js
'use strict';
/* The engine behind the prototype screens: the model it reports becomes S.acct, commands go
   out through send(), and the look (theme, wallpaper, screen effects) lands on #entry. */
let VERSION = '';
const DEFAULT_SERVER = '', DEFAULT_ONION = '';
const USER_RE = /^[a-z0-9_]{3,24}$/;
const S = {
  acct: null, look: null, tor: { state: 'off', p: 0 },
  set: { idle: 10, lock: true, lockMin: false, protect: true, hidden: false, notify: true, notifyName: false, taskbar: true, tor: true, bridges: 'off', bridgeLines: '', cover: 1, autoUpd: true, server: '', socks: '' },
};
const bus = {
  m: new Map(),
  on(ev, f) { if (!this.m.has(ev)) this.m.set(ev, new Set()); this.m.get(ev).add(f); return () => this.m.get(ev).delete(f); },
  emit(ev, d) { (this.m.get(ev) || []).forEach(f => f(d)); },
};
const lag = (a = 450, b = 900) => sleep(reduced ? 120 : a + Math.random() * (b - a));
let idleTimer = 0, pingAt = 0;
function idleReset() {
  const n = Date.now();
  if (S.acct && n - pingAt > 5000) { pingAt = n; send('ping'); }
}
['pointerdown', 'keydown', 'wheel'].forEach(ev => addEventListener(ev, idleReset, { passive: true, capture: true }));
function lockNow() { send('lock'); }

const unhex = s => new Uint8Array((String(s || '').match(/../g) || []).map(x => parseInt(x, 16)));

// ── jobs: a command, then the flash or the model says how it went ──
const eng = {
  m: null, waits: new Set(),
  until(f, ms = 20000, job = false) {
    return new Promise((res, rej) => {
      const w = { f, job, res, rej };
      w.t = setTimeout(() => { eng.waits.delete(w); rej({ key: 'err.network' }); }, ms);
      eng.waits.add(w);
    });
  },
  job(cmd, args, until, ms = 20000) {
    const p = eng.until(until || null, ms, true);
    send(cmd, args);
    return p;
  },
  done(w, ok, v) { clearTimeout(w.t); eng.waits.delete(w); (ok ? w.res : w.rej)(v); },
  err: e => (e && e.text) || t((e && e.key) || 'err.network'),
  nav(id, force) {
    if (!id || (!force && eng.m && eng.m.route === id)) return;
    const i = id.indexOf(':');
    send('nav', { to: id.slice(0, i), id: id.slice(i + 1) });
    if (eng.m) eng.m.route = id;
  },
  async lookup(u) {
    if (!mnContact(u)) await eng.job('add_contact', { username: u }, () => !!mnContact(u), 60000);
    return mnAddContact(mnContact(u));
  },
  async created(kind, cmd, args) {
    const before = new Set(S.acct.chats.map(c => c.id));
    const find = () => S.acct && S.acct.chats.find(c => (c.kind === kind || (kind === 'channel' && c.kind === 'official')) && !before.has(c.id));
    await eng.job(cmd, args, () => !!find(), 60000);
    return find() || eng.until(() => !!find(), 8000).then(find);
  },
  verify(c) { eng.nav(c.id || 'dm:' + c.username, true); send('verify', { on: true }); },
  update(s) {
    const m = s.m;
    if (m) { eng.m = m; mnSync(m); }
    const f = s.flash, fk = f ? JSON.stringify(f) : '';
    if (fk !== eng.lastFlash) {
      eng.lastFlash = fk;
      if (f) {
        const w = [...eng.waits].find(x => x.job);
        if (w) eng.done(w, f.ok, { text: f.text, key: f.ok ? null : 'err.network' });
        else flash(f.text, f.ok ? 'ok' : 'err');
        send('dismiss_flash');
      }
    }
    if (m) for (const w of [...eng.waits]) if (w.f) { let ok = false; try { ok = w.f(m); } catch (e) { /* stale */ } if (ok) eng.done(w, true, m); }
    if (s.look !== undefined) lookApply(s.look);
  },
};

// ── the model → the shapes the screens draw ──
const shKeys = new Map();
const shKey = x => { if (!shKeys.has(x)) shKeys.set(x, unhex(x)); return shKeys.get(x); };
function shMsg(o) {
  return {
    id: o.id, out: o.out, from: o.from, at: new Date(o.ts), ttl: o.ttl, exp: o.exp, state: o.state,
    text: o.sys || o.text || '', sys: !!o.sys,
    media: o.media ? [{ type: o.media.video ? 'video' : 'photo', url: o.media.url, w: o.media.w, h: o.media.h, dur: o.media.dur }] : [],
  };
}
function mnSync(m) {
  VERSION = m.version || VERSION;
  const was = S.acct;
  const a = was && was.username === m.me.u ? was : { username: m.me.u, chats: [], contacts: [] };
  Object.assign(a, { display: m.me.display, about: m.me.about, particles: m.me.particles, keys: { ed: shKey(m.me.ed), x: shKey(m.me.x) }, fp: m.me.fp, pin: m.pin || null, duress: m.duress || null });
  S.acct = a;
  Object.assign(S.set, m.set, { notify: m.set.taskbar });
  if (S.tor.state !== m.tor.state || S.tor.p !== m.tor.p) { S.tor = { ...m.tor }; bus.emit('tor', S.tor); }

  const ks = new Map(a.contacts.map(k => [k.username, k]));
  a.contacts = m.contacts.map(o => Object.assign(ks.get(o.u) || {}, { username: o.u, display: o.name === o.u ? '' : o.name, keys: { ed: shKey(o.ed), x: shKey(o.x) }, verified: o.verified, sn: o.sn, fp: o.fp, about: o.about, changed: o.changed }));

  const old = new Map(a.chats.map(c => [c.id, c]));
  const v = mn && mn.cv;
  const chats = m.chats.map(o => {
    const c = old.get(o.id) || { id: o.id, msgs: [] };
    old.delete(o.id);
    Object.assign(c, {
      kind: o.kind, peer: o.peer, title: o.title || '', owner: o.owner, about: o.about || '', mine: o.mine, warn: o.warn,
      members: [...(o.members || [])], subs: [...(o.subs || [])],
      pinned: o.pinned, muted: o.muted, ttl: o.ttl, unread: mn && mn.chat === o.id ? 0 : o.unread, at: new Date(o.last || 0),
    });
    const next = o.msgs.map(shMsg);
    if (v && v.c === c && o.full) shOpen(v, c, next);
    else if (o.full) { c.msgs = next; c.full = true; }
    else { const l = next[next.length - 1]; if (!l) c.msgs = []; else if (!c.msgs.length || c.msgs[c.msgs.length - 1].id !== l.id) c.msgs = [l]; c.full = false; }
    return c;
  });
  // a contact's chat with nothing in it yet stays while it is open
  for (const c of old.values()) if (c.kind === 'dm' && !c.msgs.some(x => !x.local) && mnContact(c.peer) && mn && mn.chat === c.id) chats.push(c);
  a.chats = chats;
  if (!was || was !== a) return;
  if (mn) {
    if (mn.chat && !mnChat(mn.chat)) { mn.chat = null; mnStage(mnEmpty()); mnDepth(0); }
    mnRenderList();
  }
}
/* the open chat: new messages fade in, sent ones take the place of their local copy,
   removed ones burn; the rest keep their nodes */
function shOpen(v, c, next) {
  if (!c.full) { c.msgs = next; c.full = true; mnFill(v); v.scroll.scrollTop = v.scroll.scrollHeight; return; }
  const have = new Map(c.msgs.filter(x => !x.local).map(x => [x.id, x]));
  const pend = c.msgs.filter(x => x.local);
  const nearEnd = v.scroll.scrollHeight - v.scroll.scrollTop - v.scroll.clientHeight < 80;
  const out = [];
  let added = false;
  for (const n of next) {
    let x = have.get(n.id);
    if (x) {
      have.delete(n.id);
      const st = x.state;
      Object.assign(x, n);
      if (st !== n.state) mnSetState(v, x);
    } else {
      const i = n.out ? pend.findIndex(p => p.text === n.text) : -1;
      if (i >= 0) {
        x = pend.splice(i, 1)[0];
        const node = v.nodes.get(x.id);
        v.nodes.delete(x.id);
        Object.assign(x, n, { local: false });
        if (node) { node.dataset.id = x.id; v.nodes.set(x.id, node); mnSetState(v, x); }
      } else {
        x = n;
        out.push(x); c.msgs = [...out];
        mnDayFor(v, x);
        const node = mnMsgNode(v, x);
        v.list.append(node);
        if (!reduced) anim(node, [{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
        added = true;
        continue;
      }
    }
    out.push(x);
  }
  for (const x of have.values()) if (mn.burn) mn.burn(x);
  c.msgs = [...out, ...pend];
  mnRuns(v);
  if (added && nearEnd) v.scroll.scrollTo({ top: v.scroll.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
}

// ── look: theme colors, wallpaper and screen effects ──
function lookStops(a, n) { const o = []; for (let i = 0; i < n; i++) o.push(a[Math.min(i, a.length - 1)]); return o; }
function lookApply(k) {
  S.look = k || null;
  const app = $('#app'), st = ENTRY.style;
  if (!k) { ['wall', 'wscope'].forEach(x => delete app.dataset[x]); fxSet('none', 'chat'); return; }
  const g = lookStops(k.bubble || ['#232328'], 3), ac = lookStops(k.accent || ['#c4302b'], 3);
  st.setProperty('--look-g', `linear-gradient(135deg, ${g.join(', ')})`);
  st.setProperty('--look-a', `linear-gradient(135deg, ${ac.join(', ')})`);
  st.setProperty('--look-a1', ac[0]);
  st.setProperty('--look-ink', k.ink || '#eeeef1');
  st.setProperty('--dim', String((k.dim || 0) / 100));
  if (k.photo) st.setProperty('--wall-img', `url("${k.photo}")`); else st.removeProperty('--wall-img');
  app.dataset.wall = k.photo || k.wall !== 'photo' ? k.wall : 'none';
  app.dataset.wscope = k.wall_scope || 'chat';
  app.dataset.theme = k.theme || 'mono';
  fxSet(reduced || k.motion === 'off' ? 'none' : k.fx || 'none', k.fx_scope || 'chat');
  bus.emit('look', k);
}
const fx = { kind: 'none', scope: 'chat', cv: null, ps: [], raf: 0, w: 0, h: 0, last: 0 };
function fxSet(kind, scope) {
  if (kind === fx.kind && scope === fx.scope) return;
  fx.kind = kind; fx.scope = scope; fx.ps = [];
  if (kind === 'none') { if (fx.cv) fx.cv.hidden = true; cancelAnimationFrame(fx.raf); fx.raf = 0; return; }
  if (!fx.cv) { fx.cv = h('canvas.fx-cv', { 'aria-hidden': 'true' }); ENTRY.append(fx.cv); }
  if (!fx.raf) { fx.last = 0; fx.raf = requestAnimationFrame(fxFrame); }
}
function fxSpawn(top) {
  const w = fx.w, ht = fx.h, k = fx.kind, R = Math.random;
  const p = { x: R() * w, y: top ? -10 : R() * ht, a: R() * 6.28 };
  if (k === 'rain') { p.v = 520 + R() * 380; p.l = 10 + R() * 14; p.o = 0.18 + R() * 0.25; }
  else if (k === 'snow') { p.v = 28 + R() * 44; p.r = 0.8 + R() * 2.2; p.o = 0.35 + R() * 0.5; }
  else if (k === 'dust') { p.v = 4 + R() * 10; p.r = 0.5 + R() * 1.3; p.o = 0.12 + R() * 0.3; p.dx = (R() - 0.5) * 10; }
  else if (k === 'embers') { if (top) p.y = ht + 10; p.v = -(24 + R() * 50); p.r = 0.7 + R() * 1.6; p.o = 0.4 + R() * 0.5; }
  else { p.v = 0; p.r = 0.4 + R() * 1.2; p.o = 0.2 + R() * 0.6; p.tw = 0.6 + R() * 2; }
  return p;
}
const FX_DENS = { rain: 5200, snow: 7000, dust: 9000, embers: 16000, stars: 5000 };
function fxFrame(now) {
  fx.raf = 0;
  if (fx.kind === 'none') return;
  fx.raf = requestAnimationFrame(fxFrame);
  const cv = fx.cv;
  if (document.hidden || ENTRY.hidden || scrName !== 'main') { cv.hidden = true; fx.last = 0; return; }
  let x0 = 0, y0 = 0, w = innerWidth, ht = innerHeight;
  if (fx.scope === 'chat') {
    const b = mn && mn.cv && mn.cv.scroll.getBoundingClientRect();
    if (!b || b.width < 2) { cv.hidden = true; return; }
    const pane = mn.cv.scroll.parentElement, hd = pane.querySelector('.ch-head'), cp = pane.querySelector('.ch-comp');
    const top = hd ? Math.max(b.top, hd.getBoundingClientRect().bottom) : b.top;
    const bot = cp ? Math.min(b.bottom, cp.getBoundingClientRect().top) : b.bottom;
    x0 = b.left; y0 = top; w = b.width; ht = Math.max(2, bot - top);
  }
  cv.hidden = false;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  if (fx.w !== w || fx.h !== ht || cv.width !== Math.round(w * dpr)) {
    fx.w = w; fx.h = ht;
    cv.width = Math.round(w * dpr); cv.height = Math.round(ht * dpr);
    cv.style.width = w + 'px'; cv.style.height = ht + 'px';
  }
  cv.style.transform = `translate(${x0}px,${y0}px)`;
  const dt = fx.last ? Math.min((now - fx.last) / 1000, 0.05) : 0;
  fx.last = now;
  const want = Math.min(420, Math.round(w * ht / (FX_DENS[fx.kind] || 8000)));
  while (fx.ps.length < want) fx.ps.push(fxSpawn(false));
  if (fx.ps.length > want) fx.ps.length = want;
  const c = cv.getContext('2d'), k = fx.kind;
  c.setTransform(dpr, 0, 0, dpr, 0, 0);
  c.clearRect(0, 0, w, ht);
  for (let i = 0; i < fx.ps.length; i++) {
    const p = fx.ps[i];
    p.a += dt;
    if (k === 'rain') {
      p.y += p.v * dt; p.x -= p.v * dt * 0.12;
      c.strokeStyle = `rgba(190,205,230,${p.o})`; c.lineWidth = 1;
      c.beginPath(); c.moveTo(p.x, p.y); c.lineTo(p.x + p.l * 0.12, p.y - p.l); c.stroke();
    } else if (k === 'stars') {
      c.fillStyle = `rgba(235,238,255,${p.o * (0.55 + 0.45 * Math.sin(p.a * p.tw))})`;
      c.fillRect(p.x, p.y, p.r * 1.6, p.r * 1.6);
      continue;
    } else {
      p.y += p.v * dt;
      p.x += (k === 'snow' ? Math.sin(p.a) * 18 : k === 'dust' ? p.dx : Math.sin(p.a * 2) * 12) * dt;
      c.fillStyle = k === 'embers' ? `rgba(255,120,60,${p.o})` : `rgba(230,232,240,${p.o})`;
      c.beginPath(); c.arc(p.x, p.y, p.r, 0, 6.283); c.fill();
    }
    if (p.y > ht + 20 || p.y < -30 || p.x < -30 || p.x > w + 30) fx.ps[i] = fxSpawn(true);
  }
}

// settings.js
/* Settings: the eight sections of 0.2.5. Every control changes the real state of the
   prototype (S.set, S.acct, Tor, the lock timer); nothing here is for show. */
const ST_SECS = [
  { id: 'profile', k: 'set.profile', icon: 'user' },
  { id: 'account', k: 'acct.profile', icon: 'at' },
  { id: 'privacy', k: 'acct.privacy', icon: 'shield' },
  { id: 'notify', k: 'acct.notifications', icon: 'bell' },
  { id: 'look', k: 'acct.appearance', icon: 'spark' },
  { id: 'net', k: 'acct.connection', icon: 'onion' },
  { id: 'data', k: 'acct.data', icon: 'archive' },
  { id: 'about', k: 'set.about', icon: 'info' },
];
const ST_NAV = [['account', 'privacy', 'notify'], ['look', 'net'], ['data', 'about']];
const ST_PFX = { none: 'pfx.none', dust: 'pfx.dust', snow: 'pfx.snow', embers: 'pfx.embers', orbit: 'pfx.orbit', rain: 'pfx.rain' };
const ST_COVER = ['off', 'std', 'high'];
const ST_PIN = /^\d{4}(\d{2})?$/;
const ST_BRIDGE = /^([a-z0-9_]+\s+)?\[?[0-9a-fA-F.:]+\]?:\d{1,5}(\s+\S+)*$/;
const stNorm = u => u.trim().replace(/\/+$/, '');

// ── the list: who you are, then the sections ─────────────
function stList(api) {
  const a = S.acct;
  const me = h('button.me', { type: 'button', 'data-sec': 'profile', 'aria-label': t('set.profile') + ': ' + a.display, 'aria-current': String(api.section === 'profile') },
    mnFace(a.keys.ed), h('span.me-t', h('b', a.display), h('small', '@' + a.username)), ico('chev', 'chev'));
  me.addEventListener('click', () => api.open('profile', me.firstChild));
  const value = { look: () => t(ST_PFX[a.particles] || ST_PFX.none), about: () => VERSION };
  const row = id => {
    const s = ST_SECS.find(x => x.id === id);
    const b = h('button.set.ico', { type: 'button', 'data-sec': id, 'aria-current': String(api.section === id) },
      h('span.s-ico', ico(s.icon)), h('span.s-l', t(s.k)), value[id] ? h('span.s-v', value[id]()) : null, ico('chev', 'chev'));
    b.addEventListener('click', () => api.open(id));
    return b;
  };
  return h('div.st-nav', me, ST_NAV.map(g => h('div.grp', g.map(row))));
}

// ── building blocks ──────────────────────────────────────
function stBlock(label, body, note) {
  return h('section.stg', label ? h('h3.grp-h', label) : null, body, note ? h('p.grp-n', note) : null);
}
/* a row with a switch; the whole row is the target */
function stCheck(label, note, on, onChange) {
  const tg = toggle(on, onChange, label);
  const row = h('div.check', h('span', label, note ? h('small', note) : null), tg);
  row.addEventListener('click', e => { if (!e.target.closest('.tg') && !tg.disabled) tg.click(); });
  row.tg = tg;
  return row;
}
function stRadios(label, opts, value, onChange) {
  const box = h('div.radios', { role: 'radiogroup', 'aria-label': label });
  const btns = opts.map(([v, text]) => h('button.radio', { type: 'button', role: 'radio', 'data-v': v }, h('span', text), h('i')));
  const mark = () => btns.forEach(b => { const on = b.dataset.v === value; b.setAttribute('aria-checked', String(on)); b.tabIndex = on ? 0 : -1; });
  btns.forEach((b, i) => {
    b.addEventListener('click', () => { if (b.dataset.v === value) return; value = b.dataset.v; mark(); onChange(value); });
    b.addEventListener('keydown', e => {
      const d = e.key === 'ArrowDown' || e.key === 'ArrowRight' ? 1 : e.key === 'ArrowUp' || e.key === 'ArrowLeft' ? -1 : 0;
      if (!d) return;
      const n = btns[(i + d + btns.length) % btns.length];
      n.focus(); n.click(); e.preventDefault();
    });
  });
  box.append(...btns);
  mark();
  box.set = v => { value = v; mark(); };
  return box;
}
function stStat(kind, icon, text) {
  const p = h('p.stat' + (kind ? '.' + kind : ''));
  if (icon) p.append(ico(icon));
  p.append(h('span', text));
  return p;
}
/* a small form in a sheet: `submit` gets the values and answers null or [field index, text] */
function stForm(title, labels, okLabel, submit, done) {
  const fs = labels.map(k => field({ label: t(k), type: 'password', inputmode: 'numeric', hardMax: 6, mono: true }));
  const okB = h('button.btn.wide', { type: 'button' }, okLabel);
  const no = h('button.btn.ghost.wide', { type: 'button' }, t('common.cancel'));
  const sh = sheet({ title, body: fs, foot: [okB, no] });
  let wait = false;
  const run = async () => {
    if (wait) return;
    wait = true;
    fs.forEach(f => f.clear());
    busy(okB, true);
    const bad = await submit(fs.map(f => f.input.value));
    busy(okB, false);
    wait = false;
    if (bad) { fs[bad[0]].error(bad[1]); fs[bad[0]].input.select(); return; }
    sh.close();
    done();
  };
  okB.addEventListener('click', run);
  no.addEventListener('click', () => sh.close());
  fs.forEach(f => f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); }));
}

// ── 1. profile ───────────────────────────────────────────
function stProfile(cx) {
  const a = S.acct;
  const name = h('h3', a.display);
  const fD = field({ label: t('f.display'), value: a.display, max: 64 });
  const fA = field({ label: t('f.about'), value: a.about, area: true, max: 140 });
  const save = h('button.btn', { type: 'button', disabled: true }, t('common.save'));
  const dirty = () => { save.disabled = fD.input.value.trim() === a.display && fA.input.value.trim() === a.about; };
  fD.input.addEventListener('input', dirty);
  fA.input.addEventListener('input', dirty);
  save.addEventListener('click', async () => {
    const d = fD.input.value.trim(), ab = fA.input.value.trim();
    if (!d || [...d].length > 64) return fD.error(t('err.display'));
    if ([...ab].length > 140) return fA.error(t('err.about_long'));
    busy(save, true);
    try { await eng.job('save_profile', { display: d, about: ab, particles: a.particles || 'dust' }); } catch (e) { busy(save, false); return fD.error(eng.err(e)); }
    busy(save, false);
    if (S.acct !== a) return;
    a.display = d; a.about = ab;
    fD.input.value = d; fA.input.value = ab; fD.count(); fA.count();
    name.textContent = d;
    dirty();
    flash(t('ok.saved'), 'ok', 2200);
    cx.api.refresh();
  });
  return [
    h('div.hud', mnFace(a.keys.ed), name, h('span.sub', '@' + a.username)),
    stBlock(null, h('div.grp', h('div.box', fD, fA, h('div.row2', save))), t('profile.note')),
  ];
}

// ── 2. account ───────────────────────────────────────────
function stAccount() {
  const a = S.acct;
  const lock = h('button.set.ico', { type: 'button' }, h('span.s-ico', ico('lock')), h('span.s-l', t('nav.lock')));
  lock.addEventListener('click', lockNow);
  return [
    h('div.grp',
      h('div.kv', h('span.t-label', t('f.username')), h('p', '@' + a.username)),
      h('div.kv', h('span.t-label', t('req.fingerprint')), h('p.t-fp', a.fp || ''))),
    h('div.grp', lock),
  ];
}

// ── 3. security and privacy ──────────────────────────────
function stPrivacy() {
  const a = S.acct;
  const pinBox = h('div.box');
  const act = (k, f) => { const b = h('button.btn.sm.ghost', { type: 'button' }, t(k)); b.addEventListener('click', f); return b; };
  const said = k => { flash(t(k), 'ok', 2400); draw(); };
  const setPin = () => stForm(t('priv.set_pin'), ['f.pin', 'f.pin_confirm'], t('common.save'), async ([p, again]) => {
    if (!ST_PIN.test(p)) return [0, t('err.pin_format')];
    if (p !== again) return [1, t('err.pin_mismatch')];
    try { await eng.job('pin_set', { pin: p, confirm: again }, m => m.pin); } catch (e) { return [0, eng.err(e)]; }
    return null;
  }, () => said('ok.pin_set'));
  const dropPin = () => {
    const gone = () => said('ok.pin_removed');
    // a PIN the server has already retired cannot be asked for
    if (a.pinGone) return gone();
    stForm(t('priv.remove_pin'), ['f.pin_current'], t('priv.remove_pin'), async ([p]) => {
      if (!ST_PIN.test(p)) return [0, t('err.pin_format')];
      try { await eng.job('pin_remove', { pin: p }, m => !m.pin); return null; } catch (e) { return [0, eng.err(e)]; }
    }, gone);
  };
  const setDuress = () => stForm(t('priv.set_duress'), ['f.pin_current', 'f.duress', 'f.pin_confirm'], t('common.save'), async ([cur, p, again]) => {
    if (!ST_PIN.test(cur)) return [0, t('err.pin_format')];
    if (!ST_PIN.test(p)) return [1, t('err.pin_format')];
    if (p === cur) return [1, t('err.duress_same')];
    if (p !== again) return [2, t('err.pin_mismatch')];
    try { await eng.job('duress_set', { pin: cur, duress: p }, m => m.duress); } catch (e) { return [1, eng.err(e)]; }
    return null;
  }, () => said('ok.duress_set'));
  const dropDuress = () => eng.job('duress_clear', {}, m => !m.duress).then(() => said('ok.duress_cleared'), e => flash(eng.err(e)));
  function draw() {
    const has = !!a.pin;
    pinBox.replaceChildren(
      ...(has ? [a.pinGone ? stStat('bad', 'warn', t('err.pin_gone')) : stStat('ok', 'check', t('priv.pin_on'))] : []),
      ...(has && a.duress ? [stStat('ok', 'check', t('priv.duress_on'))] : []),
      h('div.row2', has ? act('priv.remove_pin', dropPin) : act('priv.set_pin', setPin),
        has && !a.pinGone ? (a.duress ? act('priv.clear_duress', dropDuress) : act('priv.set_duress', setDuress)) : null));
  }
  draw();

  let pvT = 0;
  const savePriv = () => send('save_privacy', { idle_min: String(S.set.idle), protect: S.set.protect, app_lock: S.set.lock, lock_min: S.set.lockMin });
  const idle = field({ label: t('d.idle'), value: String(S.set.idle), inputmode: 'numeric', hardMax: 3, mono: true });
  idle.input.addEventListener('input', () => {
    const v = idle.input.value.trim();
    if (!/^\d{1,3}$/.test(v)) return;
    S.set.idle = +v; clearTimeout(pvT); pvT = setTimeout(savePriv, 700);
  });
  idle.input.addEventListener('change', () => { idle.input.value = String(S.set.idle); });
  const minRow = stCheck(t('priv.lock_min'), null, S.set.lockMin, v => { S.set.lockMin = v; savePriv(); });
  const dep = () => { idle.input.disabled = !S.set.lock; minRow.tg.disabled = !S.set.lock; };
  const lockRow = stCheck(t('priv.lock'), null, S.set.lock, v => { S.set.lock = v; dep(); savePriv(); });
  dep();

  return [
    stBlock(t('priv.pin'), h('div.grp', pinBox), t('priv.pin_note')),
    stBlock(t('priv.lock'), h('div.grp', lockRow, h('div.box', idle), minRow), t('priv.lock_note')),
    stBlock(null, h('div.grp', stCheck(t('priv.protect'), t('priv.protect_note'), S.set.protect, v => { S.set.protect = v; savePriv(); }))),
    stBlock(t('priv.lookup'), h('div.grp', stCheck(t('priv.hidden'), null, S.set.hidden, v => { S.set.hidden = v; send('save_hidden', { hidden: v }); })), t('priv.hidden_note')),
  ];
}

// ── 4. notifications ─────────────────────────────────────
function stNotify() {
  const a = S.acct;
  const dm = a.chats.find(c => c.kind === 'dm');
  const who = h('b'), text = h('p'), when = h('time');
  const card = h('div.notif', { 'aria-hidden': 'true' }, h('span.nk', ico('shield')), h('div', who, text), when);
  // the preview never invents a message: the text is shown as a bar, the sender is a contact
  // you really have (or a bar too)
  const draw = move => {
    const on = S.set.notify, named = on && S.set.notifyName;
    card.classList.toggle('off', !on);
    who.replaceChildren(named ? (dm ? mnTitle(dm) : h('i.bar.w40')) : 'Aegis');
    text.replaceChildren(named ? h('i.bar.w80') : t('notify.new'));
    when.textContent = hm(new Date());
    if (move) anim(card, [{ transform: 'translateY(-10px) scale(.97)', opacity: 0.2 }, { transform: 'none', opacity: on ? 1 : 0.35 }], { duration: 420, easing: E.scene });
  };
  const sv = () => send('save_notify', { on: S.set.notify, name: S.set.notifyName });
  const nameRow = stCheck(t('notify.name'), null, S.set.notifyName, v => { S.set.notifyName = v; sv(); draw(true); });
  const dep = () => { nameRow.tg.disabled = !S.set.notify; };
  const onRow = stCheck(t('notify.on'), null, S.set.notify, v => { S.set.notify = v; sv(); dep(); draw(true); });
  dep(); draw(false);
  return [
    h('div.grp', h('div.prev-wrap', card)),
    stBlock(null, h('div.grp', onRow, nameRow), t('notify.note')),
  ];
}

// ── 5. appearance ────────────────────────────────────────
function stLook(cx) {
  const a = S.acct;
  const radios = stRadios(t('f.particles'), Object.keys(ST_PFX).map(v => [v, t(ST_PFX[v])]), a.particles || 'dust', v => {
    store.set('particles', v); a.particles = v;
    send('save_profile', { display: a.display, about: a.about, particles: v });
    AegisScene.particles(v);
    cx.api.refresh();
  });
  const lang = h('div.seg.mono', { 'aria-label': t('set.language') },
    ['ru', 'en'].map(v => h('button', { type: 'button', 'data-v': v }, v.toUpperCase())));
  seg(lang, LANG, v => {
    LANG = v; store.set('lang', v); document.documentElement.lang = v; send('set_lang', { lang: v });
    // the shell is rebuilt in the new language and comes back to this section
    setTimeout(() => {
      if (!S.acct || scrName !== 'main') return;
      go('main', { tr: 'none' });
      mnSetView('settings');
      mnOpenSection('look');
    }, reduced ? 0 : 280);
  });
  return [
    ...stLookFx(cx),
    stBlock(t('f.particles'), h('div.grp', radios)),
    stBlock(null, h('div.grp', h('div.check', h('span', t('set.language'), h('small', t('set.lang_note'))), lang))),
  ];
}

// ── 6. network and Tor ───────────────────────────────────
/* what an observer of the line sees: without cover traffic the line is silent while you are
   not writing; with it, packets leave at an even pace whether you write or not */
function stCoverChart(cx, level) {
  const cv = h('canvas.cover', { role: 'img' });
  const gap = () => [0, 0.95, 0.38][level];
  let ticks = [], next = 0, last = 0, id = 0, w = 0, hgt = 0;
  const size = () => {
    const r = cv.getBoundingClientRect(), d = Math.min(devicePixelRatio || 1, 2);
    w = r.width; hgt = r.height;
    cv.width = Math.round(w * d); cv.height = Math.round(hgt * d);
    cv.getContext('2d').setTransform(d, 0, 0, d, 0, 0);
  };
  const paint = () => {
    const g = cv.getContext('2d'), mid = Math.round(hgt / 2) + 0.5;
    g.clearRect(0, 0, w, hgt);
    g.strokeStyle = '#26262b'; g.lineWidth = 1;
    g.beginPath(); g.moveTo(12, mid); g.lineTo(w - 12, mid); g.stroke();
    g.strokeStyle = '#eeeef1'; g.lineWidth = 2; g.lineCap = 'round';
    for (const k of ticks) {
      const x = w - 12 - k.age * 46;
      g.globalAlpha = Math.min(1, k.age * 5) * Math.min(1, Math.max(0, (x - 12) / 40)) * 0.85;
      g.beginPath(); g.moveTo(x, mid - 11); g.lineTo(x, mid + 11); g.stroke();
    }
    g.globalAlpha = 1;
  };
  const still = () => { ticks = []; if (level) for (let x = 0.2; x * 46 < w - 24; x += gap()) ticks.push({ age: x }); paint(); };
  const frame = now => {
    id = 0;
    if (!cv.isConnected) return;
    const dt = Math.min(0.1, (now - last) / 1000 || 0);
    last = now;
    ticks.forEach(k => { k.age += dt; });
    ticks = ticks.filter(k => k.age * 46 < w);
    if (level) { next -= dt; if (next <= 0) { ticks.push({ age: 0 }); next = gap(); } }
    paint();
    if (level || ticks.length) id = requestAnimationFrame(frame);
  };
  const wake = () => { if (reduced) return still(); if (!id) { last = performance.now(); id = requestAnimationFrame(frame); } };
  const ro = new ResizeObserver(() => { if (!cv.isConnected) return; size(); if (reduced) still(); else { paint(); wake(); } });
  ro.observe(cv);
  cx.off(() => { ro.disconnect(); cancelAnimationFrame(id); });
  cv.set = v => { level = v; next = 0; wake(); };
  return cv;
}
function stNet(cx) {
  const st = h('p.stat'), bar = h('div.torbar', h('i'));
  const shown = () => S.set.server;
  const conn = o => ({ endpoint: S.set.server, socks5: S.set.socks, tor: S.set.tor, cover: ST_COVER[S.set.cover] || 'std', bridges: S.set.bridges, bridge_lines: S.set.bridgeLines, ...o });
  const ep = field({ label: t('f.endpoint'), value: shown(), mono: true, inputmode: 'url' });
  const socks = field({ label: t('d.socks5'), value: S.set.socks, mono: true });
  const draw = () => {
    const k = !S.set.tor ? 'off' : S.tor.state;
    st.className = 'stat' + (k === 'ready' ? ' ok' : '');
    st.replaceChildren(ico(k === 'ready' ? 'check' : k === 'off' ? 'warn' : 'onion'),
      h('span', k === 'ready' ? t('conn.tor_ready') : k === 'off' ? t('conn.tor_off') : t('conn.tor_start') + ' · ' + S.tor.p + '%'));
    bar.hidden = k !== 'start';
    bar.style.setProperty('--p', S.tor.p / 100);
    socks.input.disabled = S.set.tor;
  };
  cx.off(bus.on('tor', draw));
  const torRow = stCheck(t('conn.tor'), null, S.set.tor, async v => {
    if (v) { S.set.tor = true; ep.input.value = shown(); ep.clear(); send('save_connection', conn()); return; }
    torRow.tg.set(true);
    const yes = await ask({ title: t('dlg.tor_off'), text: t('dlg.tor_off_text'), ok: t('dlg.tor_off_ok') });
    if (!yes || !S.acct) return;
    send('save_connection', conn({ tor: false })); send('confirm_tor_off');
    S.set.tor = false; torRow.tg.set(false); ep.input.value = shown(); ep.clear();
  });
  draw();

  // bridges
  const lines = field({ label: t('f.bridge_lines'), value: S.set.bridgeLines, area: true, mono: true });
  const keep = h('button.btn.sm', { type: 'button' }, t('common.save'));
  const lineBox = h('div.box', { hidden: S.set.bridges !== 'custom' }, lines, h('div.row2', keep));
  const brOpts = [['off', 'conn.bridges_off'], ['snowflake', 'conn.bridges_snowflake'], ['obfs4', 'conn.bridges_obfs4'], ['custom', 'conn.bridges_custom']];
  const bridges = stRadios(t('conn.bridges'), brOpts.map(([v, k]) => [v, t(k)]), S.set.bridges, v => {
    const open = v === 'custom';
    if (open !== !lineBox.hidden) {
      lineBox.hidden = !open;
      if (open) anim(lineBox, [{ opacity: 0, transform: 'translateY(-8px)' }, { opacity: 1, transform: 'none' }], { duration: 320, easing: E.out });
    }
    // own bridges take effect once their lines are saved
    if (open) return;
    S.set.bridges = v;
    send('save_connection', conn());
  });
  keep.addEventListener('click', async () => {
    const rows = lines.input.value.split('\n').map(x => x.trim()).filter(Boolean);
    if (!rows.length) return lines.error(t('err.bridges_empty'));
    if (rows.length > 20) return lines.error(t('err.bridges_many'));
    const bad = rows.findIndex(x => !ST_BRIDGE.test(x));
    if (bad >= 0) return lines.error(errText('err.bridge_line', bad + 1));
    busy(keep, true);
    try { await eng.job('save_connection', conn({ bridges: 'custom', bridge_lines: rows.join('\n') })); } catch (e) { busy(keep, false); return lines.error(eng.err(e)); }
    busy(keep, false);
    if (!S.acct) return;
    lines.input.value = S.set.bridgeLines;
    flash(t('ok.saved'), 'ok', 2200);
  });

  // server address, proxy, test
  const res = h('p.stat', { 'aria-live': 'polite', hidden: true });
  const say = (kind, icon, text) => { res.hidden = false; res.className = 'stat' + (kind ? ' ' + kind : ''); res.replaceChildren(...(icon ? [ico(icon)] : []), h('span', text)); };
  const save = h('button.btn.sm', { type: 'button' }, t('common.save'));
  const test = h('button.btn.sm.ghost', { type: 'button' }, t('set.test'));
  save.addEventListener('click', async () => {
    const url = stNorm(ep.input.value), sx = socks.input.value.trim();
    let ok = false;
    try { const u = new URL(url); ok = /^https?:$/.test(u.protocol) && !!u.hostname; } catch (e) { ok = false; }
    if (!ok) return ep.error(t('err.endpoint'));
    if (!S.set.tor && sx && !/^[^\s:/]+:\d{1,5}$/.test(sx)) return socks.error(t('err.socks'));
    busy(save, true);
    try { await eng.job('save_connection', conn({ endpoint: url, socks5: S.set.tor ? S.set.socks : sx })); } catch (e) { busy(save, false); return ep.error(eng.err(e)); }
    busy(save, false);
    if (!S.acct) return;
    res.hidden = true;
    flash(t('ok.saved'), 'ok', 2200);
  });
  test.addEventListener('click', async () => {
    say('', '', t('conn.running'));
    busy(test, true);
    let r = null;
    try { r = [true, await eng.job('test_conn', { endpoint: stNorm(ep.input.value), socks5: socks.input.value.trim(), tor: S.set.tor }, null, 60000)]; } catch (e) { r = [false, eng.err(e)]; }
    busy(test, false);
    if (!res.isConnected) return;
    if (r[0]) say('ok', 'check', r[1] || t('conn.ok')); else say('bad', 'warn', r[1]);
  });

  // cover traffic
  const chart = stCoverChart(cx, S.set.cover);
  const cvOpts = [['0', 'conn.cover_off'], ['1', 'conn.cover_std'], ['2', 'conn.cover_high']];
  const label = () => chart.setAttribute('aria-label', t('conn.cover') + ': ' + t(cvOpts[S.set.cover][1]));
  const cover = h('div.seg', { 'aria-label': t('conn.cover') }, cvOpts.map(([v, k]) => h('button', { type: 'button', 'data-v': v }, t(k))));
  seg(cover, String(S.set.cover), v => { S.set.cover = +v; chart.set(+v); label(); send('save_connection', conn()); });
  label();

  return [
    stBlock(null, h('div.grp', torRow, h('div.box', st, bar)), t('conn.tor_note')),
    stBlock(t('conn.bridges'), h('div.grp', bridges, lineBox), t('conn.bridges_note')),
    stBlock(t('d.server'), h('div.grp', h('div.box', ep, socks, h('div.row2', save, test), res)), t('set.conn_note')),
    stBlock(t('conn.cover'), h('div.grp', h('div.box', cover, chart)), t('conn.cover_note')),
  ];
}

// ── 7. backup and removal ────────────────────────────────
function stData() {
  const a = S.acct;
  const path = field({ label: t('f.export_path'), mono: true });
  const exp = h('button.btn.sm', { type: 'button' }, t('set.export'));
  exp.addEventListener('click', async () => {
    path.clear();
    busy(exp, true);
    try {
      path.ok(await eng.job('export', { path: path.input.value.trim() }, null, 120000));
    } catch (err) {
      path.error(eng.err(err));
    }
    busy(exp, false);
  });
  path.input.addEventListener('keydown', e => { if (e.key === 'Enter') exp.click(); });

  const del = h('button.btn.sm.danger', { type: 'button' }, t('d.delete_here'));
  del.addEventListener('click', async () => {
    const f = field({ label: t('f.confirm_name'), mono: true });
    f.check = () => {
      if (f.input.value.trim().replace(/^@/, '').toLowerCase() === a.username) return true;
      f.error(t('err.confirm_name'));
      return false;
    };
    const yes = await ask({ title: t('set.danger'), text: t('dlg.delete_account_text') + ' ' + a.username + '.', ok: t('d.delete_ok'), extra: f });
    if (!yes || S.acct !== a) return;
    send('open_dialog', { kind: 'delete_account' });
    send('delete_account', { confirm: a.username });
  });
  return [
    stBlock(null, h('div.grp', h('div.box', path, h('div.row2', exp))), t('set.backup_note')),
    stBlock(t('set.danger'), h('div.grp', h('div.box', h('p.note', t('set.delete_note')), h('div.row2', del)))),
  ];
}

// ── 8. about ─────────────────────────────────────────────
function stAbout() {
  const res = h('p.stat', { 'aria-live': 'polite', hidden: true });
  const chk = h('button.btn.sm.ghost', { type: 'button' }, t('upd.check'));
  chk.addEventListener('click', async () => {
    res.hidden = false; res.className = 'stat'; res.replaceChildren(h('span', t('upd.checking')));
    busy(chk, true);
    send('update_now');
    // a manual check also downloads; the build is ~16 MB in 1 MB chunks, slow over Tor, so show the progress
    const u = await eng.until(m => {
      if (/^Downloading/.test(m.update) && res.isConnected) res.replaceChildren(h('span', t('upd.downloading') + (m.update_pct != null ? ' · ' + m.update_pct + '%' : '')));
      return !/^(Idle|Checking|Downloading)/.test(m.update);
    }, 30 * 60000).then(m => m.update, () => 'Failed');
    busy(chk, false);
    if (!res.isConnected) return;
    const k = /^Current/.test(u) ? 'd.upd_none' : /^Ready/.test(u) ? 'upd.ready' : /^Available/.test(u) ? 'upd.available' : 'upd.failed';
    res.className = 'stat ' + (k === 'upd.failed' ? 'bad' : 'ok');
    res.replaceChildren(ico(k === 'upd.failed' ? 'warn' : 'check'), h('span', t(k)));
    if (k === 'upd.ready') { const ins = h('button.btn.sm', { type: 'button' }, t('upd.restart')); ins.addEventListener('click', () => send('install_update')); res.append(ins); }
  });
  return [
    h('div.grp',
      h('div.kv', h('span.t-label', t('upd.version')), h('p', 'Aegis ' + VERSION)),
      h('div.kv', h('p', t('set.about_text')), h('p.note', t('set.about_font')))),
    stBlock(t('upd.title'), h('div.grp',
      stCheck(t('upd.auto'), null, S.set.autoUpd, v => { S.set.autoUpd = v; send('save_updates', { auto_update: v }); }),
      h('div.box', h('div.row2', chk), res)), t('upd.note')),
  ];
}

const ST_BUILD = { profile: stProfile, account: stAccount, privacy: stPrivacy, notify: stNotify, look: stLook, net: stNet, data: stData, about: stAbout };

function stSection(id, api) {
  const s = ST_SECS.find(x => x.id === id) || ST_SECS[0];
  const offs = [];
  const back = h('button.ib.bare.back-phone', { type: 'button', 'aria-label': t('nav.settings') }, ico('back'));
  back.addEventListener('click', () => api.back());
  const blocks = ST_BUILD[s.id]({ api, off: f => offs.push(f) });
  const el = h('div.sec', { 'data-sec': s.id }, h('div.sec-in', h('div.sec-top', back, h('h2.t-sheet', t(s.k))), blocks));
  el._off = () => offs.forEach(f => f());
  // the blocks arrive as a ladder; the profile face is left alone, the avatar flies into it
  blocks.filter(b => b && !b.classList.contains('hud')).forEach((b, i) =>
    anim(b, [{ opacity: 0, transform: 'translateY(14px)' }, { opacity: 1, transform: 'none' }], { duration: 440, delay: 60 + i * 55, easing: E.out, fill: 'backwards' }));
  return el;
}

// ── look: theme, wallpaper, effects (the engine keeps them) ──
const ST_THEMES = ['mono', 'ocean', 'dusk', 'aurora', 'ember', 'slate'];
const ST_WALLS = ['none', 'solid', 'gradient', 'photo'];
const ST_FX = ['none', 'rain', 'snow', 'dust', 'embers', 'stars'];
function stLookFx(cx) {
  const L = () => S.look || {};
  const setL = (key, value) => send('set_look', { key, value: String(value) });
  const theme = h('div.seg.wrap', { 'aria-label': t('look.theme') }, ST_THEMES.map(v => h('button', { type: 'button', 'data-v': v }, t(`look.theme_${v}`))));
  const thS = seg(theme, L().theme || '', v => setL('theme', v));
  const walls = stRadios(t('look.wallpaper'), ST_WALLS.map(v => [v, t(`look.wallpaper_${v}`)]), L().wall || 'none', v => {
    if (v === 'photo') send('pick_wall'); else setL('wallpaper', v);
  });
  const pick = h('button.btn.sm.ghost', { type: 'button' }, t('look.photo_pick'));
  pick.addEventListener('click', () => send('pick_wall'));
  const scope = (key, cur) => {
    const b = h('div.seg', { 'aria-label': t('look.scope') }, ['chat', 'full'].map(v => h('button', { type: 'button', 'data-v': v }, t(`look.scope_${v}`))));
    b.s = seg(b, cur || 'chat', v => setL(key, v));
    return b;
  };
  const dim = h('input.range', { type: 'range', min: '0', max: '90', step: '1', value: String(L().dim || 0), 'aria-label': t('look.dim') });
  dim.addEventListener('input', () => ENTRY.style.setProperty('--dim', String(dim.value / 100)));
  dim.addEventListener('change', () => setL('wall_dim', dim.value));
  const fx = stRadios(t('look.effect'), ST_FX.map(v => [v, t(`look.fx_${v}`)]), L().fx || 'none', v => setL('effect', v));
  const anim = stCheck(t('look.animated'), null, !!L().animated, v => setL('animated', v ? 'on' : 'off'));
  const reset = h('button.btn.sm.ghost', { type: 'button' }, t('look.reset'));
  reset.addEventListener('click', () => send('reset_look'));
  const wS = scope('wall_scope', L().wall_scope), fS = scope('effect_scope', L().fx_scope);
  cx.off(bus.on('look', k => {
    walls.set(k.wall || 'none'); fx.set(k.fx || 'none');
    if (k.theme && thS.value !== k.theme) thS.set(k.theme, true);
    if (wS.s.value !== (k.wall_scope || 'chat')) wS.s.set(k.wall_scope || 'chat', true);
    if (fS.s.value !== (k.fx_scope || 'chat')) fS.s.set(k.fx_scope || 'chat', true);
    if (document.activeElement !== dim) dim.value = String(k.dim || 0);
  }));
  return [
    stBlock(t('look.theme'), h('div.grp', h('div.box', theme))),
    stBlock(t('look.wallpaper'), h('div.grp', walls, h('div.box', h('div.check', h('span', t('look.scope')), wS), h('label.check', h('span', t('look.dim')), dim), h('div.row2', pick)))),
    stBlock(t('look.effect'), h('div.grp', fx, h('div.box', h('div.check', h('span', t('look.scope')), fS)))),
    stBlock(null, h('div.grp', anim, h('div.box', h('div.row2', reset)))),
  ];
}

// main.js
'use strict';
/* Main: list, chat, contact HUD, media, sheets.
   Everything shown comes from what the user did in this session; nothing
   arrives on its own. The only unread posts are the four of the official channel.
   Layout: under 900 px three push panes (data-depth 0/1/2); 900-1239 list + stage,
   info as an overlay; from 1240 list / stage / info in a grid. */

// limits of 0.2.5 (media.rs MAX_INPUT, mp4clean.rs MAX_VIDEO, channel.rs, newgroup.note)
const MN_MAX_TEXT = 4096, MN_MAX_GROUP = 100, MN_MAX_SUBS = 200, MN_MAX_PHOTO = 40 << 20, MN_MAX_VIDEO = 31 << 20;
const MN_TTL = [
  { v: 0, k: 'ttl.off' }, { v: 30, k: 'ttl.30s' }, { v: 300, k: 'ttl.5m' },
  { v: 3600, k: 'ttl.1h' }, { v: 86400, k: 'ttl.1d' }, { v: 604800, k: 'ttl.7d' },
];
const MN_INV_RE = /^aegis:\/\/invite\/\S+$/;
const mnInvites = new Map();   // invites created this session: link → { used }
let mn = null;                 // the mounted main screen

// ── data ─────────────────────────────────────────────────
function mnSeed() {}
const mnNet = () => !S.set.tor || S.tor.state === 'ready';
const mnChat = id => S.acct && S.acct.chats.find(c => c.id === id);
const mnContact = u => S.acct && S.acct.contacts.find(c => c.username === u);
const mnLast = c => c.msgs[c.msgs.length - 1];
const mnOwner = c => c.kind === 'channel' && c.owner === S.acct.username;
// the official channel takes posts only from the account holding the compiled-in owner key
const mnCanWrite = c => c.kind === 'dm' || c.kind === 'group' || mnOwner(c) || (c.kind === 'official' && !!c.mine);
function mnTitle(c) {
  if (c.kind !== 'dm') return c.title;
  const k = mnContact(c.peer);
  return (k && k.display) || '@' + c.peer;
}
function mnText(m) { return m.post ? t(m.post) : m.text || ''; }
function mnPreview(m) {
  if (!m) return '';
  if (m.media && m.media.length) return (m.media[0].type === 'video' ? t('media.video') : t('media.photo')) + (m.media.length > 1 ? ' ×' + m.media.length : '');
  return mnText(m).replace(/\s+/g, ' ');
}
function mnTime(d) {
  const n = new Date();
  return d.toDateString() === n.toDateString() ? hm(d) : pad(d.getDate()) + '.' + pad(d.getMonth() + 1);
}
const mnActive = c => { const m = mnLast(c); return m ? +m.at : +c.at; };
/* avatars as in render.rs: a contact's own key; groups, channels and strangers get a key
   hashed from their id. The markup is kept per key: the list redraws on every keystroke */
const mnFaces = new Map();
const mnIdKey = id => sha256(cat(enc.encode('aegis ui avatar'), enc.encode(id)));
function mnKeyOf(u) {
  const k = mnContact(u);
  return k ? k.keys.ed : u === S.acct.username ? S.acct.keys.ed : mnIdKey(u);
}
function mnFace(key, cls = '') {
  const id = hex(key);
  if (!mnFaces.has(id)) mnFaces.set(id, identicon(key));
  return h('span.av.id' + cls, { 'aria-hidden': 'true', html: mnFaces.get(id) });
}
const mnAv = (c, cls = '') => mnFace(c.kind === 'dm' ? mnKeyOf(c.peer) : mnIdKey(c.id), cls);
function mnTtlLabel(v) { const o = MN_TTL.find(x => x.v === v) || MN_TTL[0]; return t(o.k); }
function mnAddContact(k) {
  const a = S.acct;
  let c = mnContact(k.username);
  if (!c) { c = { username: k.username, display: k.display || '', keys: k.keys, verified: false, about: k.about || '' }; a.contacts.push(c); }
  let ch = a.chats.find(x => x.kind === 'dm' && x.peer === c.username);
  if (!ch) { ch = { id: 'dm:' + c.username, kind: 'dm', peer: c.username, msgs: [], ttl: 0, pinned: false, muted: false, unread: 0, at: new Date() }; a.chats.push(ch); }
  return ch;
}
/* expired disappearing messages leave the data at once; the open chat burns its own */
function mnSweep() {
  if (!S.acct) return;
  const now = Date.now();
  let gone = false;
  for (const c of S.acct.chats) {
    const keep = c.msgs.filter(m => !(m.exp && m.exp <= now));
    if (keep.length !== c.msgs.length) {
      const dead = c.msgs.filter(m => !keep.includes(m));
      c.msgs = keep; gone = true;
      if (mn && mn.chat === c.id && mn.burn) dead.forEach(m => mn.burn(m));
      dead.forEach(mnFreeMedia);
    }
  }
  if (gone && mn) mnRenderList();
}
function mnFreeMedia(m) { (m.media || []).forEach(x => { try { URL.revokeObjectURL(x.url); } catch (e) { /* already gone */ } }); }

// ── shell ────────────────────────────────────────────────
function scrMain() {
  const a = S.acct;
  mnSeed(a);
  mnSweep();
  const el = h('div.main', { 'data-depth': '0', 'data-info': '0' });
  const paneL = h('div.pane-l'), paneS = h('div.pane-s'), paneI = h('div.pane-i');
  el.append(paneL, paneS, paneI);
  mn = { el, paneL, paneS, paneI, view: 'chats', filter: 'all', q: '', chat: null, sec: null, info: false, burn: null, offs: [], timers: new Set() };

  // list column
  const roll = h('h1.roll', { 'data-v': '0', 'aria-live': 'polite' }, h('span', t('d.chats')), h('span', t('nav.settings')));
  const setB = h('button.ib.bare', { type: 'button', 'aria-label': t('nav.settings'), 'aria-pressed': 'false' }, ico('sliders'));
  const moreB = h('button.ib.bare', { type: 'button', 'aria-label': t('menu.more'), 'aria-haspopup': 'menu', 'aria-expanded': 'false' }, ico('menu'));
  const tabs = h('div.seg.tabs', { 'aria-label': t('d.chats') },
    h('button', { type: 'button', 'data-v': 'all' }, t('tab.all')),
    h('button', { type: 'button', 'data-v': 'groups' }, t('tab.groups')),
    h('button', { type: 'button', 'data-v': 'channels' }, t('tab.channels')));
  const q = h('input', { type: 'search', placeholder: t('list.filter'), 'aria-label': t('list.filter'), autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off' });
  const qx = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close'), hidden: true }, ico('close'));
  const list = h('div.ls-list', { role: 'list' });
  const setList = h('div.ls-list');
  const ls = h('div.ls', { 'data-view': 'chats' },
    h('div.ls-head', roll, setB, moreB),
    h('div.ls-body',
      h('div.ls-view.v-chats',
        h('div.ls-tools', tabs, h('div.find', ico('search'), q, qx)),
        h('div.ls-scroll', list)),
      h('div.ls-view.v-set', { inert: true }, h('div.ls-scroll.st-scroll', setList))));
  paneL.append(ls);
  Object.assign(mn, { ls, roll, setB, list, setList, qIn: q, qx });
  mnHl(list);

  const tabSeg = seg(tabs, 'all', v => { mn.filter = v; mnRenderList(); });
  mn.tabSeg = tabSeg;
  q.addEventListener('input', () => { mn.q = q.value; qx.hidden = !q.value; mnRenderList(); });
  q.addEventListener('keydown', e => {
    if (e.key === 'Escape' && q.value) { e.stopPropagation(); q.value = ''; q.dispatchEvent(new Event('input')); }
    if (e.key === 'Enter') { const r = list.querySelector('.row'); if (r) r.click(); }
  });
  qx.addEventListener('click', () => { q.value = ''; q.dispatchEvent(new Event('input')); q.focus(); });
  setB.addEventListener('click', () => mnSetView(mn.view === 'chats' ? 'settings' : 'chats'));
  moreB.addEventListener('click', () => menu(moreB, [
    { icon: 'at', label: t('nav.new_chat'), run: () => mnNewChat() },
    { icon: 'users', label: t('nav.new_group'), run: mnNewGroup },
    { icon: 'channel', label: t('nav.new_channel'), run: mnNewChannel },
    { icon: 'user', label: t('nav.contacts'), run: mnContacts },
    { icon: 'link', label: t('inv.title'), run: mnInvite },
    '-',
    { icon: 'lock', label: t('nav.lock'), run: lockNow },
  ]));
  list.addEventListener('click', e => {
    const r = e.target.closest('.row');
    if (!r) return;
    if (r.classList.contains('lookup')) mnLookup(r.dataset.u, r);
    else mnOpenChat(r.dataset.id);
  });

  // stage + info
  paneS.append(h('div.stage'));
  paneI.append(h('div.info-host'));
  mn.stage = paneS.firstChild;

  mnTorLine();
  mnRenderList();
  mnStage(mnEmpty());

  const onResize = () => mnScene();
  const onKey = e => {
    if (e.key !== 'Escape' || e.defaultPrevented || openSheets.length || openMenu || $('.viewer')) return;
    if (mn.info) { mnCloseInfo(); return; }
    if (mn.search) { mn.search.close(); return; }
    if (!isDesk() && (mn.chat || mn.sec)) mnBack();
  };
  addEventListener('resize', onResize);
  document.addEventListener('keydown', onKey);
  const sweepId = setInterval(mnSweep, 1000);
  mn.offs.push(
    () => removeEventListener('resize', onResize),
    () => document.removeEventListener('keydown', onKey),
    () => clearInterval(sweepId),
    bus.on('tor', () => { mnTorLine(); if (mn.onTor) mn.onTor(); }),
  );

  el._enter = () => mnScene();
  el._off = () => {
    const m = mn;
    if (!m) return;
    m.offs.forEach(f => f());
    m.timers.forEach(clearTimeout);
    if (m.stage.firstChild && m.stage.firstChild._off) m.stage.firstChild._off();
    if (m.vw) m.vw.close(true);
    mn = null;
  };
  return el;
}
function mnLater(ms, f) {
  const m = mn;
  const id = setTimeout(() => { m.timers.delete(id); if (mn === m) f(); }, ms);
  m.timers.add(id);
  return id;
}

/* the 3D shield lives on the empty desktop stage only; everywhere else in the shell the
   canvas is covered by opaque panes, so the scene stops drawing */
function mnScene() {
  if (!mn || !mn.stage || !mn.list) return;
  // a view that is fading out is already inert: it no longer holds the object
  const view = mn.stage.querySelector('.view:not([inert])');
  const obj = view && view.matches('.st-empty') ? view.querySelector('.obj3d') : null;
  // the appearance section lets the scene through, so a choice of particles is seen at once
  const thru = !!view && view.dataset.sec === 'look';
  mn.paneS.classList.toggle('thru', thru);
  const lobj = !isDesk() && (mn.el.dataset.depth || '0') === '0' && mn.view === 'chats' ? $('.ls-empty .obj3d', mn.list) : null;
  mn.paneL.classList.toggle('thru', !!lobj);
  if (obj && isDesk()) AegisScene.show('shield', obj, { morph: true });
  else if (lobj) AegisScene.show('shield', lobj, { morph: true });
  else if (thru) { AegisScene.scatter(); AegisScene.show(null, null); }
  else { AegisScene.scatter(); AegisScene.rest(900); }
}

/* depth: 0 list, 1 stage, 2 info (phones); info is its own flag on desktop */
function mnDepth(d) {
  mn.el.dataset.depth = String(d);
  const desk = isDesk();
  mn.paneL.inert = !desk && d > 0;
  mn.paneS.inert = !desk && d !== 1;
  mn.paneI.inert = desk ? !mn.info : d !== 2;
  mnScene();
}
function mnBack() {
  if (mn.info) return mnCloseInfo();
  // phone: the header avatar goes back into its row while the chat slides away
  const head = mn.chat && mn.cv && !isDesk() && !reduced ? $('.ch-who .av', mn.cv.el) : null;
  const id = mn.chat, a = head && head.getBoundingClientRect();
  mn.chat = null; mn.sec = null;
  mnDepth(0);
  mnMark();
  if (head && mn.view === 'chats') {
    const av = $(`.row[data-id="${id}"] .av`, mn.list), main = mn.el.getBoundingClientRect();
    const b = av && mnRest(av, mn.paneL, main), box = av && mnRest(av.closest('.ls-scroll'), mn.paneL, main);
    if (b && b.bottom > box.top + 4 && b.top < box.bottom - 4) mnLift(head, a, b, [head, av], 560);
  }
  mnLater(reduced ? 0 : 560, () => { if (!mn.chat && !mn.sec) mnStage(mnEmpty()); });
}

/* where an element inside a sliding pane sits once the pane is at rest: panes only move and
   scale, so its offset in the pane's current box is mapped onto the resting box */
function mnRest(el, pane, rest) {
  const r = el.getBoundingClientRect(), p = pane.getBoundingClientRect(), s = p.width / rest.width || 1;
  return new DOMRect(rest.left + (r.left - p.left) / s, rest.top + (r.top - p.top) / s, r.width / s, r.height / s);
}
/* shared element: a copy of `src` flies from box a to box b above the panes; what it stands
   for stays hidden until it lands */
function mnLift(src, a, b, hide, dur) {
  const ghost = src.cloneNode(true), cs = getComputedStyle(src);
  // the copy leaves its parent, so what the parent's rules gave it travels inline
  Object.assign(ghost.style, { position: 'fixed', left: a.left + 'px', top: a.top + 'px', width: a.width + 'px', height: a.height + 'px', margin: 0, zIndex: 90, pointerEvents: 'none', transformOrigin: '0 0',
    fontSize: cs.fontSize, borderRadius: cs.borderRadius, overflow: cs.overflow, opacity: 1 });
  ghost.classList.add('lift');
  ENTRY.append(ghost);
  hide.forEach(e => { e.style.opacity = '0'; });
  return anim(ghost, [{ transform: 'none' }, { transform: `translate(${b.left - a.left}px, ${b.top - a.top}px) scale(${b.width / a.width})` }],
    { duration: dur, easing: E.scene, fill: 'forwards' }).then(() => {
    ghost.remove();
    hide.forEach(e => { e.style.opacity = ''; });
  });
}

/* stage: one view at a time; desktop crossfades, phone pushes the pane */
function mnStage(node) {
  const st = mn.stage, old = st.firstElementChild;
  node.classList.add('view');
  st.append(node);
  if (old) {
    old._off && old._off();
    old.inert = true;
    if (isDesk() && !reduced) {
      anim(node, [{ opacity: 0, transform: 'translateY(10px)' }, { opacity: 1, transform: 'none' }], { duration: 380, delay: 120, easing: E.scene, fill: 'backwards' });
      anim(old, [{ opacity: 1 }, { opacity: 0 }], { duration: 120, easing: E.out, fill: 'forwards' }).then(() => old.remove());
    } else if (!reduced && (mn.el.dataset.depth || '0') !== '0') {
      // the old view is gone before the new one shows: the two never overlap half-transparent
      anim(node, [{ opacity: 0, transform: 'translateX(18px)' }, { opacity: 1, transform: 'none' }], { duration: 280, delay: 100, easing: E.scene, fill: 'backwards' });
      anim(old, [{ opacity: 1 }, { opacity: 0 }], { duration: 100, easing: E.out, fill: 'forwards' }).then(() => old.remove());
    } else old.remove();
  }
  mnScene();
}
function mnEmpty() {
  const obj = h('div.obj3d');
  const nc = h('button.btn.sm.ghost', { type: 'button' }, ico('at'), t('nav.new_chat'));
  const inv = h('button.btn.sm.ghost', { type: 'button' }, ico('link'), t('inv.title'));
  nc.addEventListener('click', () => mnNewChat());
  inv.addEventListener('click', mnInvite);
  return h('div.st-empty', obj, h('p', t('main.pick')), h('div.chips', nc, inv));
}

// ── list ─────────────────────────────────────────────────
function mnSetView(v) {
  mn.view = v;
  mn.ls.dataset.view = v;
  mn.roll.dataset.v = v === 'settings' ? '1' : '0';
  mn.setB.setAttribute('aria-pressed', String(v === 'settings'));
  mn.setB.replaceChildren(ico(v === 'settings' ? 'back' : 'sliders'));
  mnMorphIn(mn.setB.firstChild);
  mn.setB.setAttribute('aria-label', v === 'settings' ? t('d.chats') : t('nav.settings'));
  const [vc, vs] = $$('.ls-view', mn.ls);
  vc.inert = v !== 'chats';
  vs.inert = v !== 'settings';
  if (v === 'settings') mn.setList.replaceChildren(stList(mnApi));
  else if (mn.sec) { mn.sec = null; if (isDesk()) mnStage(mnEmpty()); else mnBack(); }
}
const mnApi = {
  open: (id, from) => mnOpenSection(id, from),
  back: () => mnBack(),
  refresh: () => { if (!mn) return; mnTorLine(); mnRenderList(); if (mn.view === 'settings') mn.setList.replaceChildren(stList(mnApi)); },
  get section() { return mn && mn.sec; },
};
function mnOpenSection(id, from) {
  if (mn.view !== 'settings') mnSetView('settings');
  const same = mn.sec === id;
  mn.sec = id; mn.chat = null;
  if (mn.info) mnCloseInfo(true);
  const node = stSection(id, mnApi);
  const a = from && !same && !reduced ? from.getBoundingClientRect() : null;
  mnStage(node);
  $$('[data-sec]', mn.setList).forEach(b => b.setAttribute('aria-current', String(b.dataset.sec === id)));
  mnDepth(1);
  // your avatar in the list flies into the face of the profile
  const face = a && $('.hud > .av', node);
  if (face) {
    const b = isDesk() ? mnRest(face, node, mn.stage.getBoundingClientRect()) : mnRest(face, mn.paneS, mn.el.getBoundingClientRect());
    mnLift(from, a, b, [face], isDesk() ? 520 : 560);
  }
}

/* while Tor boots nothing can be sent: one hairline over the whole shell says how far it is;
   it leaves once Tor is up (the status itself lives in Settings, not in chips) */
function mnTorLine() {
  if (!mn) return;
  const on = S.set.tor && S.tor.state === 'start';
  let ln = mn.torLn;
  if (!on) {
    if (ln && !ln.classList.contains('done')) { ln.classList.add('done'); mnLater(reduced ? 0 : 700, () => { if (mn && mn.torLn === ln) { ln.remove(); mn.torLn = null; } }); }
    return;
  }
  if (!ln || ln.classList.contains('done')) {
    if (ln) ln.remove();
    ln = mn.torLn = h('div.tor-ln', { role: 'progressbar', 'aria-label': t('conn.tor_start'), 'aria-valuemin': '0', 'aria-valuemax': '100' }, h('i'));
    mn.el.append(ln);
  }
  ln.setAttribute('aria-valuenow', S.tor.p);
  ln.firstChild.style.transform = 'scaleX(' + Math.max(0.02, S.tor.p / 100) + ')';
}

function mnRenderList() {
  if (!mn || !S.acct) return;
  const a = S.acct, qv = mn.q.trim().toLowerCase();
  let chats = a.chats.slice();
  if (mn.filter === 'groups') chats = chats.filter(c => c.kind === 'group');
  if (mn.filter === 'channels') chats = chats.filter(c => c.kind === 'channel' || c.kind === 'official');
  if (qv) chats = chats.filter(c => (mnTitle(c) + ' ' + (c.peer || '') + ' ' + mnPreview(mnLast(c))).toLowerCase().includes(qv.replace(/^@/, '')));
  chats.sort((x, y) => (y.pinned - x.pinned) || (mnActive(y) - mnActive(x)));
  const rows = chats.map(mnRow);
  const u = qv.replace(/^@/, '');
  if (qv.startsWith('@') && USER_RE.test(u) && u !== a.username && !mnContact(u)) {
    rows.unshift(h('button.row.lookup', { type: 'button', role: 'listitem', 'data-u': u },
      h('span.av.look', { 'aria-hidden': 'true' }, ico('at')),
      h('span.r-body', h('span.r-top', h('span.r-name', h('b', '@' + u))), h('span.r-bot', h('span.r-prev', t('list.lookup') + ' @' + u)))));
  }
  const hl = mn.list.querySelector('.hl');
  // rows that stay slide to their new places (a chat that just got a message goes up); new ones fade in
  const was = !reduced && mn.view === 'chats' && (isDesk() || mn.el.dataset.depth === '0') ? new Map($$('.row[data-id]', mn.list).map(r => [r.dataset.id, r.getBoundingClientRect().top])) : null;
  mn.list.replaceChildren(...[hl, ...rows].filter(Boolean));
  if (was && was.size) for (const r of $$('.row[data-id]', mn.list)) {
    const y = was.get(r.dataset.id), d = y == null ? 0 : y - r.getBoundingClientRect().top;
    if (y == null) anim(r, [{ opacity: 0 }, { opacity: 1 }], { duration: 320, easing: E.out });
    else if (Math.abs(d) > 1) anim(r, [{ transform: `translateY(${d}px)` }, { transform: 'none' }], { duration: 460, easing: E.scene });
  }
  if (!qv && mn.filter === 'all' && !a.chats.some(c => c.kind !== 'official')) {
    const b = h('button.btn.sm', { type: 'button' }, ico('at'), t('nav.new_chat'));
    b.addEventListener('click', () => mnNewChat());
    mn.list.append(h('div.ls-empty', isDesk() ? null : h('div.obj3d'), h('p', t('list.empty')), b));
  }
  mnScene();
}
function mnRow(c) {
  const m = mnLast(c);
  const out = m && m.out;
  const name = h('span.r-name', h('b', mnTitle(c)), c.kind === 'official' ? h('span.tag', t('chan.official_tag')) : null,
    c.kind === 'group' ? ico('users') : c.kind === 'channel' ? ico('channel') : null);
  const prev = h('span.r-prev', out ? h('em', t('list.you') + ' ') : null, m ? mnPreview(m) : c.kind === 'dm' ? t('chat.empty') : '');
  const bot = h('span.r-bot', prev,
    c.ttl ? mnRing() : null,
    c.pinned ? ico('pin', 'pin-ico') : null,
    c.unread ? h('span.badge' + (c.muted ? '.muted' : ''), { 'aria-label': String(c.unread) }, c.unread) : null);
  return h('button.row', { type: 'button', role: 'listitem', 'data-id': c.id, 'aria-current': mn.chat === c.id ? 'true' : null },
    mnAv(c), h('span.r-body', h('span.r-top', name, h('time.r-time', m ? mnTime(m.at) : '')), bot));
}
function mnMark() { $$('.row[data-id]', mn.list).forEach(r => r.setAttribute('aria-current', String(r.dataset.id === mn.chat))); }

/* the highlight follows the pointer from row to row on a spring */
function mnHl(list) {
  const hl = h('i.hl', { 'aria-hidden': 'true' });
  list.append(hl);
  const sy = new Spring(0, 320, 0.8);
  let run = null, on = false;
  const render = () => { hl.style.transform = `translateY(${sy.x}px)`; };
  list.addEventListener('pointerover', e => {
    if (e.pointerType === 'touch') return;
    const r = e.target.closest('.row');
    if (!r || !list.contains(r)) return;
    if (!list.contains(hl)) list.prepend(hl);
    sy.to = r.offsetTop;
    hl.style.height = r.offsetHeight + 'px';
    if (!on) { sy.snap(); on = true; hl.style.opacity = '1'; render(); return; }
    if (!run || !run.live) run = runSprings([sy], render);
  });
  list.addEventListener('pointerleave', () => { on = false; hl.style.opacity = '0'; });
}

async function mnLookup(u, row) {
  const k = mnContact(u);
  if (k) return mnOpenChat(mnAddContact(k).id);
  if (!mnNet()) return flash(t('err.tor_boot'));
  const prev = row && row.querySelector('.r-prev');
  if (prev) prev.textContent = t('busy.lookup');
  try {
    const ch = await eng.lookup(u);
    if (!mn) return;
    mn.q = "";
    if (mn.qx) { mn.qx.hidden = true; }
    const qi = mn.ls.querySelector('.find input'); if (qi) qi.value = '';
    mnRenderList();
    mnOpenChat(ch.id);
  } catch (e) {
    if (prev) prev.textContent = t('list.lookup') + ' @' + u;
    flash(eng.err(e));
  }
}

// ── sheets: new chat, contacts, invite, group, channel ───
function mnNewChat(pre = '') {
  const f = field({ label: t('f.contact_username'), value: pre, mono: true, max: 24 });
  const ok = h('button.btn.wide', { type: 'button' }, t('newchat.add'));
  const s = sheet({ title: t('nav.new_chat'), body: [h('p.note', t('newchat.note')), f], foot: [ok] });
  const run = async () => {
    const u = f.input.value.trim().replace(/^@/, '').toLowerCase();
    if (!USER_RE.test(u)) return f.error(t('err.username'));
    if (u === S.acct.username) return f.error(t('err.self'));
    const have = mnContact(u);
    if (have) { s.close(); mnOpenChat(mnAddContact(have).id); return; }
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true);
    f.ok(t('busy.lookup'));
    try {
      const ch = await eng.lookup(u);
      busy(ok, false);
      s.close();
      if (mn) mnOpenChat(ch.id);
    } catch (e) { busy(ok, false); f.error(eng.err(e)); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

function mnContacts() {
  const cs = S.acct.contacts.slice().sort((x, y) => (x.display || x.username).localeCompare(y.display || y.username));
  let s = null;
  const body = cs.length
    ? h('div.grp', cs.map(k => {
      const b = h('button.set', { type: 'button' },
        mnFace(k.keys.ed, '.s36'),
        h('span.s-l', k.display || '@' + k.username, h('small', '@' + k.username + (k.verified ? ' · ' + t('contact.verified') : ''))),
        ico('chev', 'chev'));
      b.addEventListener('click', () => { s.close(); mnOpenChat(mnAddContact(k).id); });
      return b;
    }))
    : h('p.note', t('newgroup.no_contacts'));
  const nc = h('button.btn.ghost.wide', { type: 'button' }, ico('at'), t('nav.new_chat'));
  nc.addEventListener('click', () => { s.close(); mnNewChat(); });
  s = sheet({ title: t('nav.contacts'), body, foot: [nc] });
}

const mnQr = () => (S.invite && S.invite.qr ? Promise.resolve(S.invite.qr) : Promise.reject(new Error('qr')));
function mnInvite() {
  const qr = h('div.qr.wait', { 'aria-hidden': 'true' }, h('span.spin'));
  const link = h('code.link', { hidden: true });
  const msg = h('p.fmsg', { 'aria-live': 'polite' });
  const copy = h('button.btn.wide', { type: 'button', disabled: true }, ico('copy'), t('inv.copy'));
  const again = h('button.btn.ghost.wide', { type: 'button' }, ico('refresh'), t('inv.another'));
  const open = h('button.btn.ghost.wide', { type: 'button' }, t('inv.open_title'));
  const s = sheet({ title: t('inv.title'), body: [h('p.note', t('inv.note')), qr, link, msg], foot: [copy, again, open] });
  let cur = '';
  const make = async () => {
    msg.textContent = ''; msg.className = 'fmsg';
    if (!mnNet()) { qr.replaceChildren(); msg.textContent = t('err.tor_boot'); return; }
    busy(again, true);
    qr.className = 'qr wait'; qr.replaceChildren(h('span.spin')); copy.disabled = true; link.hidden = true;
    msg.textContent = t('busy.invite');
    try { await eng.job('create_invite', {}, m => m.invite && m.invite.link !== cur); }
    catch (e) { busy(again, false); qr.replaceChildren(); msg.textContent = eng.err(e); return; }
    cur = S.invite.link;
    mnInvites.set(cur, { used: false, at: Date.now() });
    link.textContent = cur; link.hidden = false; copy.disabled = false; msg.textContent = '';
    busy(again, false);
    try { const svg = await mnQr(cur); qr.className = 'qr'; qr.innerHTML = svg; qr.removeAttribute('aria-hidden'); qr.firstChild.setAttribute('aria-label', t('inv.title')); }
    catch (e) { qr.remove(); }
    if (!reduced) anim(link, [{ opacity: 0 }, { opacity: 1 }], { duration: 400 });
    decode(link, cur, 900);
  };
  copy.addEventListener('click', async () => { const ok = await copyText(cur, link); if (ok) flash(t('d.copied'), 'ok', 2000); });
  again.addEventListener('click', make);
  open.addEventListener('click', () => { s.close(); mnOpenInvite(); });
  make();
}
function mnOpenInvite() {
  const f = field({ label: t('f.invite_link'), mono: true });
  const ok = h('button.btn.wide', { type: 'button' }, t('inv.open'));
  const s = sheet({ title: t('inv.open_title'), body: [h('p.note', t('inv.open_note')), f], foot: [ok] });
  const run = async () => {
    const v = f.input.value.trim();
    if (!MN_INV_RE.test(v)) return f.error(t('err.invite_link'));
    if (mnInvites.has(v)) return f.error(t('err.self'));
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true); f.ok(t('busy.invite'));
    try { await eng.job('redeem_invite', { link: v }); busy(ok, false); s.close(); }
    catch (e) { busy(ok, false); f.error(eng.err(e)); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
  return s;
}

function mnPick(contacts, max, onChange) {
  const chosen = new Set();
  const n = h('span');
  const head = h('div.pick-n.t-label', h('span', t('newgroup.members')), n);
  const box = h('div.pick', { role: 'group', 'aria-label': t('newgroup.members') }, contacts.map(k => {
    const b = h('button', { type: 'button', role: 'checkbox', 'aria-checked': 'false' },
      mnFace(k.keys.ed, '.s36'),
      h('b', k.display || '@' + k.username), h('i', ico('check')));
    b.addEventListener('click', () => {
      const on = !chosen.has(k.username);
      if (on) chosen.add(k.username); else chosen.delete(k.username);
      b.setAttribute('aria-checked', String(on));
      upd();
    });
    return b;
  }));
  const upd = () => { n.textContent = chosen.size + ' / ' + max; onChange && onChange(chosen); };
  upd();
  return { el: h('div.stack', head, box), chosen };
}
function mnNewGroup() {
  const cs = S.acct.contacts;
  if (!cs.length) {
    const nc = h('button.btn.wide', { type: 'button' }, ico('at'), t('nav.new_chat'));
    const s0 = sheet({ title: t('nav.new_group'), body: [h('p.note', t('newgroup.no_contacts'))], foot: [nc] });
    nc.addEventListener('click', () => { s0.close(); mnNewChat(); });
    return;
  }
  const f = field({ label: t('f.group_title'), max: 64 });
  const p = mnPick(cs, MN_MAX_GROUP - 1);
  const err = h('p.fmsg', { 'aria-live': 'polite' });
  const ok = h('button.btn.wide', { type: 'button' }, t('newgroup.create'));
  const s = sheet({ title: t('nav.new_group'), body: [f, h('p.note', t('newgroup.note')), p.el, err], foot: [ok] });
  ok.addEventListener('click', async () => {
    const title = f.input.value.trim();
    err.textContent = '';
    if (!title || [...title].length > 64) return f.error(t('err.group_title'));
    if (!p.chosen.size) { err.textContent = t('err.group_members'); shake(p.el); return; }
    if (p.chosen.size > MN_MAX_GROUP - 1) { err.textContent = t('err.group_big'); return; }
    if (!mnNet()) { err.textContent = t('err.tor_boot'); return; }
    busy(ok, true); err.className = 'fmsg ok'; err.textContent = t('busy.group');
    let c;
    try { c = await eng.created('group', 'create_group', { title, members: [...p.chosen] }); }
    catch (e) { busy(ok, false); err.className = 'fmsg'; err.textContent = eng.err(e); return; }
    busy(ok, false);
    s.close();
    if (mn && c) { mnRenderList(); mnOpenChat(c.id); }
  });
}
function mnNewChannel() {
  const f = field({ label: t('f.channel_title'), max: 64 });
  const ok = h('button.btn.wide', { type: 'button' }, t('newchannel.create'));
  const s = sheet({ title: t('nav.new_channel'), body: [f, h('p.note', t('newchannel.note'))], foot: [ok] });
  const run = async () => {
    const title = f.input.value.trim();
    if (!title || [...title].length > 64) return f.error(t('err.channel_title'));
    if (!mnNet()) return f.error(t('err.tor_boot'));
    busy(ok, true);
    let c;
    try { c = await eng.created('channel', 'create_channel', { title, about: '', members: [] }); }
    catch (e) { busy(ok, false); return f.error(eng.err(e)); }
    busy(ok, false);
    s.close();
    if (mn && c) { mnRenderList(); mnOpenChat(c.id); }
  };
  ok.addEventListener('click', run);
  f.input.addEventListener('keydown', e => { if (e.key === 'Enter') run(); });
}

// @@chat
function mnRing(m) {
  const NS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(NS, 'svg');
  svg.setAttribute('class', 'ttl'); svg.setAttribute('viewBox', '0 0 12 12'); svg.setAttribute('aria-hidden', 'true');
  for (const c of ['tr', 'tv']) {
    const e = document.createElementNS(NS, 'circle');
    e.setAttribute('class', c); e.setAttribute('cx', '6'); e.setAttribute('cy', '6'); e.setAttribute('r', '5');
    svg.append(e);
  }
  if (m) mnRingSet(svg, m);
  return svg;
}
function mnRingSet(svg, m) {
  const left = m.exp ? Math.max(0, m.exp - Date.now()) / (m.ttl * 1000) : 1;
  svg.lastChild.style.strokeDashoffset = String(31.4 * (1 - left));
}

function mnOpenChat(id) {
  const c = mnChat(id);
  if (!c || !mn) return;
  eng.nav(id);
  // the row's avatar, if the row is on screen: the chat header takes it over
  let row = null;
  if (!reduced && mn.view === 'chats' && (isDesk() || mn.el.dataset.depth === '0')) {
    const av = $(`.row[data-id="${id}"] .av`, mn.list);
    const r = av && av.getBoundingClientRect(), box = av && av.closest('.ls-scroll').getBoundingClientRect();
    if (r && r.width && r.bottom > box.top + 4 && r.top < box.bottom - 4) row = { av, r };
  }
  if (mn.view !== 'chats') { mn.sec = null; mnSetView('chats'); }
  const was = mn.chat;
  mn.chat = id; mn.sec = null;
  c.unread = 0;
  mnRenderList();
  const fresh = was !== id || !mn.cv;
  if (fresh) mnStage(mnChatView(c));
  mnDepth(1);
  if (row && fresh && mn.cv) {
    const head = $('.ch-who .av', mn.cv.el);
    // desktop: the new view rises 10px as it fades in; phone: the whole pane slides in
    const b = isDesk() ? mnRest(head, mn.cv.el, mn.stage.getBoundingClientRect()) : mnRest(head, mn.paneS, mn.el.getBoundingClientRect());
    const now = $(`.row[data-id="${id}"] .av`, mn.list);
    mnLift(row.av, row.r, b, isDesk() || !now ? [head] : [head, now], isDesk() ? 520 : 560);
  }
  if (mn.info) { if (innerWidth >= 1240) mnOpenInfo(c, true); else mnCloseInfo(true); }
}

/* "1 участник, 3 участника, 5 участников" */
function mnMembers(n) {
  const one = n % 10 === 1 && n % 100 !== 11, few = n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14);
  if (LANG === 'en') return n + ' ' + (n === 1 ? t('group.members_1') : t('group.members_n'));
  return n + ' ' + (one ? t('group.members_1') : few ? t('group.members_2') : t('group.members_n'));
}
function mnSub(c) {
  if (c.kind === 'official') return [document.createTextNode(t('chan.official'))];
  if (c.kind === 'group') return [document.createTextNode(mnMembers(c.members.length))];
  if (c.kind === 'channel') return [document.createTextNode(t('chan.channel') + ' · ' + c.subs.length + ' ' + t('chan.subs_n'))];
  const k = mnContact(c.peer);
  const out = [k && k.verified ? h('span.vf', t('contact.verified')) : h('span', t('contact.unverified'))];
  if (c.ttl) out.push(document.createTextNode('·'), mnRing(), h('span', t('ttl.short') + ': ' + mnTtlLabel(c.ttl).toLowerCase()));
  return out;
}

function mnChatView(c) {
  const el = h('div.chat', { 'data-id': c.id });
  const back = h('button.ib.bare.back-phone', { type: 'button', 'aria-label': t('common.back') }, ico('back'));
  const sub = h('small');
  const who = h('button.ch-who', { type: 'button', 'aria-label': t('menu.info') + ': ' + mnTitle(c) }, mnAv(c, '.s40'), h('span', h('b', mnTitle(c)), sub));
  const more = h('button.ib.bare', { type: 'button', 'aria-label': t('menu.more'), 'aria-haspopup': 'menu' }, ico('more'));
  const head = h('div.ch-head.glass', back, who, more);
  const list = h('div.ch-list', { role: 'log', 'aria-label': mnTitle(c) });
  const scroll = h('div.ch-scroll', list);
  const drop = h('div.drop', { 'aria-hidden': 'true' }, h('span', t('chat.attach')));
  el.append(scroll, head, drop);
  const v = { c, el, list, scroll, sub, nodes: new Map() };

  const subUpd = () => sub.replaceChildren(...mnSub(c));
  subUpd();
  v.subUpd = subUpd;
  back.addEventListener('click', () => mnBack());
  who.addEventListener('click', () => mnOpenInfo(c));
  more.addEventListener('click', () => mnChatMenu(v, more));

  // composer, or one line saying who may write here
  if (mnCanWrite(c)) {
    const ta = h('textarea', { rows: 1, placeholder: t('chat.placeholder'), 'aria-label': t('chat.placeholder') });
    const n = h('span.cmp-n', { hidden: true });
    const send = h('button.ib.send', { type: 'button', 'aria-label': t('chat.send'), disabled: true }, ico('send'));
    const clip = h('button.ib.bare', { type: 'button', 'aria-label': t('chat.attach') }, ico('clip'));
    const file = h('input', { type: 'file', accept: 'image/*,video/*', multiple: true, hidden: true, tabIndex: -1 });
    const comp = h('div.ch-comp.glass', h('div.cmp', clip, h('div.cmp-box', ta, n), send), h('p.ch-hint', t('chat.hint')), file);
    el.append(comp);
    const fit = () => {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 160) + 'px';
      el.style.setProperty('--cp-h', comp.offsetHeight + 'px');
      const len = [...ta.value].length;
      n.hidden = len < MN_MAX_TEXT - 200;
      n.textContent = String(MN_MAX_TEXT - len);
      n.classList.toggle('over', len > MN_MAX_TEXT);
      send.disabled = !ta.value.trim();
    };
    ta.addEventListener('input', fit);
    ta.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send.click(); }
    });
    send.addEventListener('click', () => {
      const text = ta.value.trim();
      if (!text) return;
      if ([...text].length > MN_MAX_TEXT) { flash(t('err.too_long')); shake(comp.querySelector('.cmp-box')); return; }
      // where the first typed line sits, so the bubble can rise out of it
      const r = ta.getBoundingClientRect(), cs = getComputedStyle(ta);
      const from = { x: r.left + parseFloat(cs.paddingLeft), y: r.top + parseFloat(cs.paddingTop) - ta.scrollTop, ink: cs.color };
      ta.value = ''; fit();
      mnSend(v, { text }, from);
      ta.focus();
    });
    clip.addEventListener('click', () => { eng.nav(c.id); send('pick_media'); });
    v.ta = ta;
    requestAnimationFrame(fit);
  } else {
    el.append(h('div.ch-comp.glass', h('div.ch-ro', ico('lock'), h('span', t('err.channel_readonly')))));
  }

  mnFill(v);
  const tick = setInterval(() => {
    for (const [id, node] of v.nodes) {
      const r = node.querySelector('.meta .ttl'), m = c.msgs.find(x => x.id === id);
      if (r && m) mnRingSet(r, m);
    }
  }, 500);
  mn.burn = m => mnBurn(v, m);
  mn.cv = v;
  mn.onTor = null;
  el._off = () => {
    clearInterval(tick);
    if (mn && mn.cv === v) { mn.burn = null; mn.cv = null; if (mn.search) mn.search.close(true); }
  };
  requestAnimationFrame(() => { scroll.scrollTop = scroll.scrollHeight; });
  return el;
}

function mnFill(v) {
  const { c, list } = v;
  v.nodes.clear();
  const kids = [];
  if (!c.msgs.length) kids.push(h('p.sys.ch-empty', t('chat.empty')));
  if (c.ttl) kids.push(h('p.sys.ttl-on', t('chat.ttl_on')));
  let day = '';
  for (const m of c.msgs) {
    const d = dayLabel(m.at);
    if (d !== day) { day = d; kids.push(h('div.day', h('span', d))); }
    kids.push(mnMsgNode(v, m));
  }
  list.replaceChildren(...kids);
  mnRuns(v);
}
function mnTtlNote(v) {
  const was = $('.ttl-on', v.list);
  if (!v.c.ttl) { if (was) collapse(was, reduced ? 1 : 300); return; }
  if (was) return;
  const e = $('.ch-empty', v.list);
  if (e) e.after(h('p.sys.ttl-on', t('chat.ttl_on')));
  else v.list.prepend(h('p.sys.ttl-on', t('chat.ttl_on')));
}
function mnDayFor(v, m) {
  const prev = v.c.msgs[v.c.msgs.indexOf(m) - 1];
  const e = $('.ch-empty', v.list);
  if (e) e.remove();
  if (!prev || dayLabel(prev.at) !== dayLabel(m.at)) v.list.append(h('div.day', h('span', dayLabel(m.at))));
}
/* runs as in 0.2.5: neighbours from one sender on one side form a run; a date or a service
   line ends it. Inside a run the bubbles close up and only the last keeps the tail. Posts in
   channels stand alone */
function mnRuns(v) {
  const post = v.c.kind === 'channel' || v.c.kind === 'official';
  const side = n => (n && n.classList.contains('msg') ? n.dataset.side : null);
  for (const n of v.list.children) {
    if (!n.classList.contains('msg')) continue;
    n.classList.toggle('first', post || side(n.previousElementSibling) !== n.dataset.side);
    n.classList.toggle('last', post || side(n.nextElementSibling) !== n.dataset.side);
  }
}

function mnMeta(m) {
  const meta = h('span.meta');
  if (m.state === 'sending') meta.append(h('span', t('msg.sending')));
  else if (m.state === 'failed') {
    const r = h('button.retry', { type: 'button' }, t('msg.retry'));
    r.addEventListener('click', e => { e.stopPropagation(); mnRetry(m); });
    meta.append(h('span', t('msg.failed') + ' ·'), r);
  } else {
    if (m.exp) meta.append(mnRing(m));
    meta.append(h('time', hm(m.at)));
    if (m.out) meta.append(ico('lock', 'lk'));
  }
  return meta;
}
function mnMsgNode(v, m) {
  const post = v.c.kind === 'channel' || v.c.kind === 'official';
  const node = h('div.msg' + (m.out ? '.out' : '.in') + (post ? '.post' : '') + (m.state === 'failed' ? '.fail' : ''), { 'data-id': m.id, 'data-side': m.out ? 'out' : 'in:' + (m.from || '') });
  if (m.media && m.media.length) {
    node.classList.add('media');
    node.append(mnAlbum(v, m));
    if (m.cap) { node.classList.add('has-cap'); node.append(h('div.cap', m.cap)); }
  } else node.append(h('span.tx', mnText(m)));
  node.append(mnMeta(m));
  v.nodes.set(m.id, node);
  return node;
}
function mnSetState(v, m) {
  const node = v && v.nodes.get(m.id);
  if (!node) return;
  node.classList.toggle('fail', m.state === 'failed');
  node.querySelector('.meta').replaceWith(mnMeta(m));
}

/* send: the text appears as cipher, then resolves; the network decides the rest.
   From the composer (`from`: the first typed line) the bubble rises out of the field */
async function mnSend(v, part, from) {
  const c = v.c;
  const m = { id: uid('m'), out: true, at: new Date(), state: 'sending', ...part };
  c.msgs.push(m);
  if (m.text) { m.local = true; eng.nav(c.id); send('send', { text: m.text }); }
  while (c.msgs.length > 1000) mnFreeMedia(c.msgs.shift());
  const ref = v.list.lastElementChild, y0 = ref ? ref.getBoundingClientRect().top : 0;
  mnDayFor(v, m);
  const node = mnMsgNode(v, m);
  const tx = node.querySelector('.tx');
  const rise = !!(from && tx && !reduced);
  v.list.append(node);
  mnRuns(v);
  // cipher glyphs are not as wide as the letters: the bubble keeps its size while they resolve
  if (tx && !reduced) {
    const box = node.getBoundingClientRect();
    node.style.width = box.width + 'px';
    node.style.height = box.height + 'px';
    if (!rise) tx.textContent = '';
  }
  let landed = null;
  if (rise) landed = mnRise(v, node, from, ref, y0);
  else {
    if (!reduced) anim(node, [{ opacity: 0, transform: 'translateY(14px) scale(.98)' }, { opacity: 1, transform: 'none' }], { duration: 420, easing: E.scene });
    v.scroll.scrollTo({ top: v.scroll.scrollHeight, behavior: reduced ? 'auto' : 'smooth' });
  }
  mnRenderList();
  const cipher = () => (tx ? scramble(tx, m.text, 1300) : Promise.resolve());
  const free = () => { node.style.width = node.style.height = ''; };
  await (landed ? landed.then(cipher) : cipher()).then(free);
  return m;
}
/* the list jumps to the end at once and glides up from where it was; a copy of the new
   bubble flies from the typed line to its place, its body and time fading in on the way,
   and the real bubble takes over where the copy lands */
function mnRise(v, node, from, ref, y0) {
  v.scroll.scrollTop = v.scroll.scrollHeight;
  const b = node.getBoundingClientRect(), line = node.querySelector('.tx').getClientRects()[0] || b;
  const dy = ref && ref.isConnected ? y0 - ref.getBoundingClientRect().top : 0;
  if (dy > 1 && dy < 420) anim(v.list, [{ transform: `translateY(${dy}px)` }, { transform: 'none' }], { duration: 460, easing: E.scene });
  const ghost = node.cloneNode(true);
  ghost.classList.add('rise');
  ghost.removeAttribute('data-id');
  Object.assign(ghost.style, { position: 'fixed', left: b.left + 'px', top: b.top + 'px', width: b.width + 'px', height: b.height + 'px', margin: 0, zIndex: 90, pointerEvents: 'none' });
  const body = h('i.rise-bg', { 'aria-hidden': 'true' });
  ghost.prepend(body);
  ENTRY.append(ghost);
  node.style.opacity = '0';
  const ink = getComputedStyle(node).color;
  return Promise.all([
    anim(ghost, [{ transform: `translate(${from.x - line.left}px, ${from.y - line.top}px)`, color: from.ink }, { transform: 'none', color: ink }], { duration: 540, easing: E.scene }),
    anim(body, [{ opacity: 0, transform: 'scale(.94)' }, { opacity: 1, transform: 'none' }], { duration: 340, delay: 60, easing: E.out, fill: 'backwards' }),
    anim(ghost.querySelector('.meta'), [{ opacity: 0 }, { opacity: 1 }], { duration: 300, delay: 200, easing: E.out, fill: 'backwards' }),
  ]).then(() => {
    ghost.remove();
    node.style.opacity = '';
  });
}
function mnDeliver() {}
async function mnRetry(m) {
  const v = mn && mn.cv;
  if (!v) return;
  if (!mnNet()) { flash(t('err.tor_boot')); shake(v.nodes.get(m.id)); return; }
  m.state = 'sending';
  mnSetState(v, m);
  eng.nav(v.c.id);
  send('retry', { id: m.id });
}

/* disappearing: text turns to ash, media fades, then the row folds */
function mnBurn(v, m) {
  const node = v.nodes.get(m.id);
  if (!node) return;
  v.nodes.delete(m.id);
  const tx = node.querySelector('.tx');
  const out = tx ? ash(tx) : reduced ? Promise.resolve() : anim(node, [{ opacity: 1, filter: 'none' }, { opacity: 0, filter: 'blur(6px) grayscale(1)' }], { duration: 1000, easing: E.soft, fill: 'forwards' });
  out.then(() => collapse(node, reduced ? 1 : 400)).then(() => {
    for (const d of $$('.day', v.list)) { const nx = d.nextElementSibling; if (!nx || nx.classList.contains('day')) d.remove(); }
    if (mn && mn.cv === v) mnRuns(v);
  });
}

// ── chat menu ────────────────────────────────────────────
function mnChatMenu(v, btn) {
  const c = v.c;
  const end = c.kind === 'dm' ? { icon: 'trash', label: t('dlg.delete_chat'), danger: true, run: () => mnDeleteChat(c) }
    : c.kind === 'group' ? { icon: 'leave', label: t('group.leave'), danger: true, run: () => mnLeave(c) }
    : mnOwner(c) ? { icon: 'trash', label: t('chan.delete'), danger: true, run: () => mnLeave(c) }
    : null;
  menu(btn, [
    { icon: 'info', label: t('menu.info'), run: () => mnOpenInfo(c) },
    { icon: 'pin', label: t(c.pinned ? 'menu.unpin' : 'menu.pin'), run: () => { c.pinned = !c.pinned; eng.nav(c.id); send('pin'); mnRenderList(); } },
    { icon: 'bell', label: t(c.muted ? 'menu.unmute' : 'menu.mute'), run: () => { c.muted = !c.muted; eng.nav(c.id); send('mute'); mnRenderList(); } },
    c.kind === 'dm' ? { icon: 'timer', label: t('ttl.label'), run: () => mnTtlSheet(v) } : null,
    { icon: 'search', label: t('chat.search'), run: () => mnSearch(v) },
    c.kind !== 'official' && c.msgs.length ? { icon: 'archive', label: t('menu.clear'), run: () => mnClear(v) } : null,
    end ? '-' : null,
    end,
  ]);
}

function mnTtlSheet(v) {
  const c = v.c;
  let s = null;
  const box = h('div.grp', { role: 'radiogroup', 'aria-label': t('ttl.label') }, MN_TTL.map(o => {
    const b = h('button.radio', { type: 'button', role: 'radio', 'aria-checked': String(c.ttl === o.v) }, h('span', t(o.k)), o.v ? mnRing() : null, h('i'));
    b.addEventListener('click', () => {
      $$('.radio', box).forEach(x => x.setAttribute('aria-checked', String(x === b)));
      if (c.ttl !== o.v) {
        c.ttl = o.v;
        eng.nav(c.id); send('set_ttl', { ttl: o.v });
        v.subUpd(); mnRenderList();
        mnTtlNote(v);
        mnRuns(v);
        v.scroll.scrollTop = v.scroll.scrollHeight;
      }
      mnLater(reduced ? 0 : 260, () => s.close());
    });
    return b;
  }));
  s = sheet({ title: t('ttl.label'), body: [box, h('p.note', t('chat.ttl_on') + '…')] });
}

async function mnClear(v) {
  const c = v.c;
  const ok = await ask({ title: t('menu.clear'), text: t('dlg.clear_text'), ok: t('menu.clear') });
  if (!ok || !mn) return;
  eng.nav(c.id); send('open_dialog', { kind: 'clear_chat', id: '' }); send('clear_chat');
  const msgs = c.msgs.slice();
  c.msgs = [];
  const nodes = $$('.msg', v.list);
  await Promise.all(nodes.map((n, i) => sleep(reduced ? 0 : Math.min(i, 20) * 35).then(() => {
    const tx = n.querySelector('.tx');
    return tx ? ash(tx, { max: 120 }) : reduced ? null : anim(n, [{ opacity: 1 }, { opacity: 0 }], { duration: 700, fill: 'forwards' });
  })));
  msgs.forEach(mnFreeMedia);
  if (mn && mn.cv === v) mnFill(v);
  mnRenderList();
}

async function mnDeleteChat(c) {
  const ok = await ask({ title: t('dlg.delete_chat'), text: t('dlg.delete_chat_text'), ok: t('contact.delete') });
  if (ok && mn) mnDrop(c, true);
}
async function mnLeave(c) {
  const own = mnOwner(c), grp = c.kind === 'group';
  const label = own ? t('chan.delete') : grp ? t('group.leave') : t('chan.leave');
  const ok = await ask({ title: label, text: own ? t('dlg.clear_text') : grp ? t('group.leave_note') : t('chan.leave_note'), ok: label });
  if (ok && mn) mnDrop(c, false);
}
/* the row folds away; the stage returns to its empty view */
async function mnDrop(c, contact) {
  const a = S.acct, cid = c.id.slice(c.id.indexOf(':') + 1);
  const kind = c.kind === 'dm' ? 'delete_chat' : c.kind === 'group' ? 'leave_group' : 'leave_channel';
  send('open_dialog', { kind, id: cid }); send(kind);
  c.msgs.forEach(mnFreeMedia);
  a.chats = a.chats.filter(x => x !== c);
  if (contact && c.peer) a.contacts = a.contacts.filter(k => k.username !== c.peer);
  if (mn.info) mnCloseInfo(true);
  if (mn.chat === c.id) {
    mn.chat = null;
    if (isDesk()) mnStage(mnEmpty()); else mnBack();
  }
  const row = mn.list.querySelector(`.row[data-id="${c.id}"]`);
  if (row) await collapse(row, reduced ? 1 : 400);
  mnRenderList();
}

// ── search inside the chat: the header turns into a field ─
function mnSearch(v) {
  if (mn.search) return mn.search.input.focus();
  const head = $('.ch-head', v.el);
  const kept = [...head.children];
  const input = h('input', { type: 'search', placeholder: t('chat.search'), 'aria-label': t('chat.search'), autocomplete: 'off', spellcheck: 'false' });
  const hits = h('span.hits.t-time', { 'aria-live': 'polite' });
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const box = h('div.ch-find', h('div.find', ico('search'), input), hits, x);
  kept.forEach(k => { k.hidden = true; });
  head.append(box);
  if (!reduced) anim(box, [{ opacity: 0, transform: 'scaleX(.6)', transformOrigin: 'right center' }, { opacity: 1, transform: 'none' }], { duration: 380, easing: E.scene });
  input.focus();
  let marks = [], cur = -1;
  const restore = () => {
    for (const [id, node] of v.nodes) {
      const tx = node.querySelector('.tx'), m = v.c.msgs.find(z => z.id === id);
      if (tx && m && tx.querySelector('mark')) tx.textContent = mnText(m);
    }
  };
  const step = i => {
    if (!marks.length) return;
    if (marks[cur]) marks[cur].classList.remove('cur');
    cur = (i + marks.length) % marks.length;
    marks[cur].classList.add('cur');
    marks[cur].scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' });
    hits.textContent = (cur + 1) + '/' + marks.length;
  };
  // marks are built from text nodes; message text never goes through innerHTML
  const run = () => {
    restore();
    marks = []; cur = -1;
    const q = input.value.trim().toLowerCase();
    if (q) for (const m of v.c.msgs) {
      const node = v.nodes.get(m.id), tx = node && node.querySelector('.tx');
      if (!tx) continue;
      const s = mnText(m), low = s.toLowerCase();
      let i = low.indexOf(q), from = 0;
      if (i < 0) continue;
      const parts = [];
      while (i >= 0) {
        parts.push(document.createTextNode(s.slice(from, i)));
        const mk = h('mark', s.slice(i, i + q.length));
        parts.push(mk); marks.push(mk);
        from = i + q.length; i = low.indexOf(q, from);
      }
      parts.push(document.createTextNode(s.slice(from)));
      tx.replaceChildren(...parts);
    }
    if (marks.length) step(marks.length - 1); else hits.textContent = q ? '0/0' : '';
  };
  const close = quick => {
    restore();
    box.remove();
    kept.forEach(k => { k.hidden = false; });
    if (mn) mn.search = null;
    if (!quick) $('.ch-who', head).focus();
  };
  input.addEventListener('input', run);
  input.addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); step(cur + (e.shiftKey ? 1 : -1)); }
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
  });
  x.addEventListener('click', () => close());
  mn.search = { input, close };
}

// @@info
// ── info pane: contact HUD, group, channel ───────────────
function mnOpenInfo(c, swap) {
  if (!mn) return;
  const from = !swap && mn.cv && mn.cv.c === c ? $('.ch-who .av', mn.cv.el) : null;
  const old = mn.paneI.firstElementChild;
  if (old && old._off) old._off();
  const node = c.kind === 'dm' ? mnHud(c) : mnGroupInfo(c);
  mn.paneI.replaceChildren(node);
  mn.info = true;
  mn.el.dataset.info = '1';
  mnDepth(isDesk() ? 1 : 2);
  if (from && !reduced) mnFlight(from, node);
  mnLater(reduced ? 0 : 300, () => { const f = $('.info-top .ib', node); if (f && isDesk()) f.focus({ preventScroll: true }); });
}
function mnCloseInfo(quick) {
  if (!mn || !mn.info) return;
  const node = mn.paneI.firstElementChild;
  // the face goes back into the chat header while the pane leaves
  const face = !quick && !reduced && node && mn.cv && mn.chat ? mnInfoFace(node) : null;
  const head = face && $('.ch-who .av', mn.cv.el), a = face && face.getBoundingClientRect();
  mn.info = false;
  mn.el.dataset.info = '0';
  mnDepth(mn.chat || mn.sec ? 1 : 0);
  if (head && a.bottom > 8 && a.top < innerHeight - 8) {
    const b = isDesk() ? head.getBoundingClientRect() : mnRest(head, mn.paneS, mn.el.getBoundingClientRect());
    mnLift(face, a, b, [face, head], 560);
  }
  mnLater(quick || reduced ? 0 : 560, () => { if (!mn.info && node && node.isConnected) { node._off && node._off(); node.remove(); } });
  if (!quick && mn.cv) $('.ch-who', mn.cv.el).focus({ preventScroll: true });
}

/* shared element: the header avatar flies into the info pane (a contact's key face, a group's
   or channel's avatar) and lands where the block settles */
function mnInfoFace(node) { return $('.hud .face', node) || $('.hud > .av', node); }
function mnFlight(from, node) {
  const face = mnInfoFace(node);
  if (!face) return;
  const a = from.getBoundingClientRect();
  const pane = mn.paneI.getBoundingClientRect(), main = mn.el.getBoundingClientRect();
  const f = face.getBoundingClientRect();
  // the block still sits 12px low (it rises as it fades in): aim where it settles
  const block = face.closest('.info-body > *');
  const rise = block ? new DOMMatrix(getComputedStyle(block).transform).m42 : 0;
  const finalLeft = isDesk() ? main.right - Math.min(380, main.width) : main.left;
  const b = new DOMRect(finalLeft + (f.left - pane.left), f.top - rise, f.width, f.height);
  mnLift(from, a, b, [face], 620).then(() => {
    if (face.isConnected) anim(face, [{ transform: 'scale(1.06)' }, { transform: 'none' }], { duration: 380, easing: E.out });
  });
}
function mnInfoTop(title) {
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico(isDesk() ? 'close' : 'back'));
  x.addEventListener('click', () => mnCloseInfo());
  return h('div.info-top', x, h('h2.t-sheet', title), h('span', { style: { width: '44px' } }));
}

// a label or icon that changes in place: the old state blurs out, the new one sharpens in
function mnMorphIn(el) {
  return anim(el, [{ opacity: 0, filter: 'blur(6px)', transform: 'scale(.8)' }, { opacity: 1, filter: 'blur(0)', transform: 'none' }], { duration: 320, easing: E.out });
}

function mnHud(c) {
  const k = mnContact(c.peer);
  const me = S.acct;
  const name = (k && k.display) || '@' + c.peer;
  const face = h('div.face', { html: identicon(k.keys.ed) });
  const st = h('span.st' + (k.verified ? '.ok' : ''), ico(k.verified ? 'check' : 'warn'), t(k.verified ? 'contact.verified' : 'contact.unverified'));
  const fp = (k.fp || '').split(' ');
  const hud = h('div.hud', face, h('h3', name), k && k.display ? h('span.sub', '@' + c.peer) : null, st);

  const act = (icon, label, pressed, run) => {
    const b = h('button.act', { type: 'button', 'aria-pressed': pressed == null ? null : String(pressed) }, ico(icon), h('span', label));
    b.addEventListener('click', () => run(b));
    return b;
  };
  const snBox = h('div.sn' + (k.verified ? '.ok' : ''), { 'aria-label': t('contact.safety') }, (k.sn || '').split(' ').filter(Boolean).map(g => h('span', [...g].map(d => h('b', d)))));
  const verB = k.verified ? null : h('button.btn.sm', { type: 'button' }, ico('check'), t('contact.mark_verified'));
  const snKv = h('div.kv', h('span.t-label', t('contact.safety')), snBox, h('p.note', t('contact.safety_note')), verB);
  const acts = h('div.acts',
    act('send', t('contacts.chat'), null, () => { if (!isDesk()) mnCloseInfo(); else if (mn.cv && mn.cv.ta) mn.cv.ta.focus(); }),
    act(c.muted ? 'sound-off' : 'sound', t('d.sound'), !c.muted, b => { c.muted = !c.muted; eng.nav(c.id); send('mute'); b.setAttribute('aria-pressed', String(!c.muted)); const i = ico(c.muted ? 'sound-off' : 'sound'); b.firstChild.replaceWith(i); mnMorphIn(i); mnRenderList(); }),
    act('shield', t('d.verify'), null, () => { snKv.scrollIntoView({ block: 'center', behavior: reduced ? 'auto' : 'smooth' }); if (verB) mnLater(reduced ? 0 : 350, () => verB.focus()); }));

  if (verB) verB.addEventListener('click', async () => {
    verB.disabled = true;
    eng.verify(c);
    const cells = $$('b', snBox);
    await Promise.all(cells.map((b, i) => sleep(reduced ? 0 : i * 50).then(() => {
      mnLater(reduced ? 0 : 350, () => b.classList.add('ok'));
      return anim(b, [{ transform: 'rotateX(0)' }, { transform: 'rotateX(90deg)' }, { transform: 'rotateX(0)' }], { duration: 700, easing: E.soft });
    })));
    if (!mn) return;
    k.verified = true;
    snBox.classList.add('ok');
    verB.remove();
    st.className = 'st ok';
    st.replaceChildren(ico('check'), t('contact.verified'));
    mnMorphIn(st);
    if (mn.cv && mn.cv.c === c) mn.cv.subUpd();
    flash(t('contact.key_verified'), 'ok', 2400);
  });

  const del = h('button.btn.danger.wide', { type: 'button' }, ico('trash'), t('contact.delete'));
  del.addEventListener('click', () => mnDeleteChat(c));
  const body = h('div.info-body', hud, acts,
    h('div.grp',
      k.about ? h('div.kv', h('span.t-label', t('d.about_short')), h('p', k.about)) : null,
      snKv,
      h('div.kv', h('span.t-label', t('req.fingerprint')), h('p.t-fp', fp.join(' ')))),
    mnMediaTabs(c), del);
  const el = h('div.info', { role: 'complementary', 'aria-label': t('contact.title') }, mnInfoTop(t('contact.title')), body);
  if (!reduced) $$('.info-body > *', el).forEach((n, i) => anim(n, [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 480, delay: 120 + i * 60, easing: E.scene, fill: 'backwards' }));
  return el;
}

function mnMediaTabs(c) {
  const all = c.msgs.flatMap(m => (m.media || []).map(x => ({ x, m })));
  const tabs = h('div.seg.tabs', h('button', { type: 'button', 'data-v': 'img' }, t('media.photo')), h('button', { type: 'button', 'data-v': 'video' }, t('media.video')));
  const grid = h('div');
  const draw = v => {
    const items = all.filter(z => z.x.type === v);
    if (!items.length) { grid.className = 'mempty'; grid.replaceChildren(t('media.none')); return; }
    grid.className = 'mgrid';
    grid.replaceChildren(...items.map((z, i) => {
      const b = h('button', { type: 'button', 'aria-label': t(v === 'img' ? 'media.photo' : 'media.video') + ' ' + (i + 1) },
        z.x.type === 'video' ? h('video', { src: z.x.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: z.x.url, alt: '' }));
      b.addEventListener('click', () => mnViewer(items.map(q => q.x), i, b));
      return b;
    }));
    if (!reduced) [...grid.children].forEach((b, k) => anim(b, [{ opacity: 0, transform: 'scale(.9)' }, { opacity: 1, transform: 'none' }], { duration: 400, delay: Math.min(k, 11) * 26, easing: E.scene, fill: 'backwards' }));
  };
  const sg = seg(tabs, 'img', draw);
  draw(sg.value || 'img');
  return h('div.mtabs', h('span.t-label', t('info.media')), tabs, grid);
}

function mnGroupInfo(c) {
  const me = S.acct.username;
  const nameOf = u => u === me ? (S.acct.display || '@' + me) + ' · ' + t('group.you') : ((mnContact(u) || {}).display || '@' + u);
  const hd = h('div.hud', mnAv(c, '.s72'),
    h('h3', mnTitle(c)), h('span.sub', mnSub(c).map(n => n.textContent).join('')),
    c.kind === 'official' ? h('span.tag', t('chan.official_tag')) : null);
  const parts = [hd];
  const mute = h('button.act', { type: 'button', 'aria-pressed': String(!c.muted) }, ico(c.muted ? 'sound-off' : 'sound'), h('span', t('d.sound')));
  mute.addEventListener('click', () => { c.muted = !c.muted; eng.nav(c.id); send('mute'); mute.setAttribute('aria-pressed', String(!c.muted)); const i = ico(c.muted ? 'sound-off' : 'sound'); mute.firstChild.replaceWith(i); mnMorphIn(i); mnRenderList(); });
  const srch = h('button.act', { type: 'button' }, ico('search'), h('span', t('chat.search')));
  srch.addEventListener('click', () => { if (!isDesk()) mnCloseInfo(); if (mn.cv) mnSearch(mn.cv); });
  const pin = h('button.act', { type: 'button', 'aria-pressed': String(!!c.pinned) }, ico('pin'), h('span', t(c.pinned ? 'menu.unpin' : 'menu.pin')));
  pin.addEventListener('click', () => { c.pinned = !c.pinned; eng.nav(c.id); send('pin'); pin.setAttribute('aria-pressed', String(c.pinned)); pin.lastChild.textContent = t(c.pinned ? 'menu.unpin' : 'menu.pin'); mnRenderList(); });
  parts.push(h('div.acts', mute, srch, pin));

  if (c.kind === 'group') {
    const resend = h('button.btn.ghost.sm', { type: 'button' }, ico('refresh'), t('group.resend'));
    resend.addEventListener('click', async () => {
      if (!mnNet()) return flash(t('err.tor_boot'));
      send('nav', { to: 'group_info', id: c.id.slice(6) });
      c.members.filter(u => u !== me).forEach(u => send('resend_invite', { member: u }));
      eng.nav(c.id, true);
    });
    parts.push(h('div.grp',
      h('div.grp-h', h('span.t-label', t('newgroup.members')), h('span.grp-n', c.members.length + ' / ' + MN_MAX_GROUP)),
      h('div.members', c.members.map(u => h('div.member', mnFace(mnKeyOf(u), '.s36'), h('b', nameOf(u)), u === c.owner ? h('small.t-tag', t('group.creator')) : null)))),
    resend);
  }
  if (mnOwner(c)) {
    const free = S.acct.contacts.filter(k => !c.subs.includes(k.username));
    const sub = h('div.grp', h('div.grp-h', h('span.t-label', t('chan.subs_n')), h('span.grp-n', c.subs.length + ' / ' + MN_MAX_SUBS)),
      c.subs.length ? h('div.members', c.subs.map(u => h('div.member', mnFace(mnKeyOf(u), '.s36'), h('b', nameOf(u))))) : null);
    parts.push(sub);
    if (free.length) {
      const p = mnPick(free, MN_MAX_SUBS - c.subs.length);
      const inv = h('button.btn.wide', { type: 'button' }, ico('users'), t('chan.invite'));
      inv.addEventListener('click', async () => {
        if (!p.chosen.size) { shake(p.el); return; }
        if (c.subs.length + p.chosen.size > MN_MAX_SUBS) return flash(t('err.channel_big'));
        if (!mnNet()) return flash(t('err.tor_boot'));
        busy(inv, true);
        send('nav', { to: 'channel_info', id: c.id.slice(8) });
        try { await eng.job('invite_channel', { members: [...p.chosen] }); }
        catch (e) { busy(inv, false); eng.nav(c.id, true); return flash(eng.err(e)); }
        busy(inv, false); eng.nav(c.id, true);
        c.subs.push(...p.chosen);
        flash(okText('ok.invite_sent', [...p.chosen].map(u => '@' + u).join(', ')), 'ok', 3000);
        if (mn && mn.cv) mn.cv.subUpd();
        if (mn) mnOpenInfo(c, true);
      });
      parts.push(p.el, inv);
    }
  }
  parts.push(mnMediaTabs(c));
  if (c.kind !== 'official') {
    const label = mnOwner(c) ? t('chan.delete') : c.kind === 'group' ? t('group.leave') : t('chan.leave');
    const out = h('button.btn.danger.wide', { type: 'button' }, ico(mnOwner(c) ? 'trash' : 'leave'), label);
    out.addEventListener('click', () => mnLeave(c));
    parts.push(out);
  }
  const el = h('div.info', { role: 'complementary', 'aria-label': t(c.kind === 'group' ? 'group.info' : 'chan.manage') },
    mnInfoTop(t(c.kind === 'group' ? 'group.info' : c.kind === 'official' ? 'chan.official' : 'chan.manage')), h('div.info-body', parts));
  if (!reduced) $$('.info-body > *', el).forEach((n, i) => anim(n, [{ opacity: 0, transform: 'translateY(12px)' }, { opacity: 1, transform: 'none' }], { duration: 480, delay: 120 + i * 60, easing: E.scene, fill: 'backwards' }));
  return el;
}

// @@media
/* photos are re-encoded: longest side 1600 px, JPEG 80; that also drops EXIF */
async function mnPhoto(file) {
  const url0 = URL.createObjectURL(file);
  try {
    const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = rej; i.src = url0; });
    const k = Math.min(1, 1600 / Math.max(img.naturalWidth, img.naturalHeight));
    const w = Math.max(1, Math.round(img.naturalWidth * k)), hh = Math.max(1, Math.round(img.naturalHeight * k));
    const cv = document.createElement('canvas');
    cv.width = w; cv.height = hh;
    cv.getContext('2d').drawImage(img, 0, 0, w, hh);
    const blob = await new Promise(res => cv.toBlob(res, 'image/jpeg', 0.8));
    if (!blob) throw new Error('enc');
    return { type: 'img', url: URL.createObjectURL(blob), w, h: hh, kb: Math.max(1, Math.round(blob.size / 1024)) };
  } finally { URL.revokeObjectURL(url0); }
}
async function mnVideo(file) {
  const url = URL.createObjectURL(file);
  const meta = await new Promise(res => {
    const v = document.createElement('video');
    v.preload = 'metadata'; v.muted = true;
    const done = ok => res(ok ? { w: v.videoWidth, h: v.videoHeight, dur: v.duration } : null);
    v.onloadedmetadata = () => done(true);
    v.onerror = () => done(false);
    setTimeout(() => done(false), 4000);
    v.src = url;
  });
  if (!meta) { URL.revokeObjectURL(url); throw new Error('bad'); }
  return { type: 'video', url, w: meta.w || 16, h: meta.h || 9, dur: meta.dur, kb: Math.round(file.size / 1024) };
}
async function mnAttach(v, files) {
  const media = [];
  for (const f of files) {
    const img = /^image\//.test(f.type), vid = /^video\//.test(f.type);
    if (!img && !vid) { flash(errText('err.media_type', f.name)); continue; }
    if (f.size > (img ? MN_MAX_PHOTO : MN_MAX_VIDEO)) { flash(errText('err.media_big', f.name)); continue; }
    try { media.push(await (img ? mnPhoto(f) : mnVideo(f))); } catch (e) { flash(errText('err.media_bad', f.name)); }
  }
  if (!media.length || !mn || mn.cv !== v) { media.forEach(x => URL.revokeObjectURL(x.url)); return; }
  const photos = media.filter(x => x.type === 'img');
  const cap = media.length === 1 && photos.length === 1 ? tf('d.compressed', { w: photos[0].w, h: photos[0].h, kb: photos[0].kb }) : '';
  mnSend(v, { media, cap });
}
const mnDur = s => (isFinite(s) ? Math.floor(s / 60) + ':' + pad(Math.floor(s % 60)) : '');
function mnAlbum(v, m) {
  const n = m.media.length, show = m.media.slice(0, 4);
  const alb = h('div.alb', { 'data-n': String(Math.min(n, 4)) });
  if (n === 1) alb.style.setProperty('--ar', m.media[0].w + ' / ' + m.media[0].h);
  show.forEach((x, i) => {
    const b = h('button', { type: 'button', 'aria-label': t(x.type === 'img' ? 'media.photo' : 'media.video') + ' ' + (i + 1) + '/' + n },
      x.type === 'video' ? h('video', { src: x.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: x.url, alt: '', decoding: 'async' }),
      x.type === 'video' ? h('span.vbadge', ico('play'), mnDur(x.dur)) : null,
      i === 3 && n > 4 ? h('span.more', '+' + (n - 4)) : null);
    b.addEventListener('click', () => mnViewer(m.media, i, b));
    alb.append(b);
  });
  if (m.state === 'sending' && !reduced) {
    // the seal: a line closes around the album while it is encrypted and sent
    const NS = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(NS, 'svg');
    svg.setAttribute('class', 'seal'); svg.setAttribute('aria-hidden', 'true');
    const r = document.createElementNS(NS, 'rect');
    r.setAttribute('x', '1'); r.setAttribute('y', '1'); r.setAttribute('rx', '15');
    r.setAttribute('width', 'calc(100% - 2px)'); r.setAttribute('height', 'calc(100% - 2px)');
    r.setAttribute('pathLength', '1'); r.style.strokeDasharray = '1';
    svg.append(r);
    alb.append(svg);
    $$('img,video', alb).forEach(e => anim(e, [{ filter: 'blur(14px) saturate(0)', transform: 'scale(1.08)' }, { filter: 'none', transform: 'none' }], { duration: 640, easing: E.scene }));
    anim(r, [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 1150, delay: 200, easing: E.soft, fill: 'forwards' })
      .then(() => anim(svg, [{ opacity: 1 }, { opacity: 0 }], { duration: 300, fill: 'forwards' })).then(() => svg.remove());
  }
  return alb;
}

// ── viewer: flies out of its cell; zoom, pan, pages, filmstrip; flies back into the cell of the current item ─
function mnViewer(items, i0, cell) {
  if (mn && mn.vw) mn.vw.close(true);
  let i = i0, cur = null, peek = null, holed = null, closed = false, out = false, tapT = 0, g = null;
  let lastTap = { at: 0, x: 0, y: 0 };
  const z = { s: 1, x: 0, y: 0 }, pts = new Map(), many = items.length > 1;
  const lim = (v, a, b) => Math.min(b, Math.max(a, v));
  const stage = h('div.v-stage'), shade = h('div.v-bg'), count = h('span.t-hud');
  const zb = h('button.ib.bare', { type: 'button', 'aria-label': t('d.zoom_in') }, ico('zoom'));
  const x = h('button.ib.bare', { type: 'button', 'aria-label': t('common.close') }, ico('close'));
  const p = h('button.ib.v-nav.p', { type: 'button', 'aria-label': t('common.back') }, ico('back'));
  const nx = h('button.ib.v-nav.n', { type: 'button', 'aria-label': t('guide.next') }, ico('next'));
  const thumbs = many ? items.map((it, j) => {
    const b = h('button', { type: 'button', 'aria-label': t(it.type === 'img' ? 'media.photo' : 'media.video') + ' ' + (j + 1) + '/' + items.length },
      it.type === 'video' ? h('video', { src: it.url, muted: true, playsInline: true, preload: 'metadata' }) : h('img', { src: it.url, alt: '', decoding: 'async' }));
    b.addEventListener('click', () => show(j));
    return b;
  }) : [];
  const strip = many ? h('div.v-strip') : null;
  if (strip) strip.append(...thumbs);
  const el = h('div.viewer.quiet', { role: 'dialog', 'aria-modal': 'true', 'aria-label': t('info.media') }, shade, stage, h('div.v-top', count, h('div.v-acts', zb, x)), p, nx, strip);

  // the cell an item came from (albums show four cells at most), and the gap it leaves there
  const cellAt = j => { const c = cell && cell.parentElement && cell.parentElement.children[j]; return c && c.tagName === 'BUTTON' ? c : null; };
  const hole = j => { const c = j < 0 ? null : cellAt(j); if (holed && holed !== c) holed.style.visibility = ''; holed = c; if (c) c.style.visibility = 'hidden'; };
  const pic = () => cur && cur.firstChild;
  const make = j => { const it = items[j]; return h('div.v-item', it.type === 'video' ? h('video', { src: it.url, controls: true, playsInline: true }) : h('img', { src: it.url, alt: '' })); };
  const run = () => { const m = pic(); if (m && m.tagName === 'VIDEO') { const q = m.play(); if (q && q.catch) q.catch(() => {}); } };
  const tfm = (b, r, s) => `translate(${r.left + r.width / 2 - b.left - b.width / 2}px, ${r.top + r.height / 2 - b.top - b.height / 2}px) scale(${s})`;
  // the part of the picture its cell shows (object-fit: cover), as a clip on the full picture
  const crop = (a, b, s, rad) => `inset(${Math.max(0, (b.height - a.height / s) / 2)}px ${Math.max(0, (b.width - a.width / s) / 2)}px round ${rad / s}px)`;
  const radOf = c => (c.parentElement.dataset.n === '1' ? 16 : 0);

  // ── zoom ──
  const apply = () => {
    const m = pic();
    if (!m) return;
    m.style.transform = z.s === 1 ? '' : `translate(${z.x}px, ${z.y}px) scale(${z.s})`;
    const on = z.s > 1;
    if (el.classList.contains('zoomed') === on) return;
    el.classList.toggle('zoomed', on);
    zb.replaceChildren(on ? ico('zoomout') : ico('zoom'));
    mnMorphIn(zb.firstChild);
    zb.setAttribute('aria-label', on ? t('d.zoom_out') : t('d.zoom_in'));
  };
  const zoomAt = (px, py, to) => {
    const m = pic();
    if (!m || m.tagName !== 'IMG') return;
    const ns = lim(to, 1, 5), r = stage.getBoundingClientRect(), k = ns / z.s;
    const cx = px == null ? 0 : px - r.left - r.width / 2, cy = py == null ? 0 : py - r.top - r.height / 2;
    const mx = Math.max(0, (m.offsetWidth * ns - r.width) / 2), my = Math.max(0, (m.offsetHeight * ns - r.height) / 2);
    z.x = lim(cx - (cx - z.x) * k, -mx, mx); z.y = lim(cy - (cy - z.y) * k, -my, my); z.s = ns;
    apply();
  };
  const zoomTo = (to, px, py) => {
    const m = pic();
    if (!m || m.tagName !== 'IMG') return;
    const from = m.style.transform || 'none';
    zoomAt(px, py, to);
    anim(m, [{ transform: from }, { transform: m.style.transform || 'none' }], { duration: 380, easing: E.scene });
  };

  // ── pages ──
  const sync = () => {
    const it = items[i], f = document.activeElement, dur = it.type === 'video' ? mnDur(it.dur) : '';
    count.textContent = (i + 1) + ' / ' + items.length + (it.type === 'img' ? ' · ' + it.w + '×' + it.h + ' · ' + it.kb + ' KB' : dur ? ' · ' + dur : '');
    p.hidden = i === 0; nx.hidden = i === items.length - 1; zb.hidden = it.type !== 'img';
    if ((f === p && p.hidden) || (f === nx && nx.hidden) || (f === zb && zb.hidden)) x.focus({ preventScroll: true });
    thumbs.forEach((b, j) => { if (j === i) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current'); });
    if (strip) { const b = thumbs[i]; strip.scrollTo({ left: b.offsetLeft - (strip.clientWidth - b.offsetWidth) / 2, behavior: reduced ? 'auto' : 'smooth' }); }
    if (out) hole(i);
  };
  const show = (j, dx = 0) => {
    if (closed || j === i || j < 0 || j >= items.length) return;
    const d = j > i ? 1 : -1, W = stage.clientWidth + 24, old = cur, reuse = peek && peek.j === j;
    const nw = reuse ? peek.el : make(j);
    if (peek && !reuse) peek.el.remove();
    peek = null;
    if (old.firstChild.tagName === 'VIDEO') old.firstChild.pause();
    z.s = 1; z.x = z.y = 0;
    i = j; cur = nw;
    if (!nw.isConnected) stage.append(nw);
    apply(); sync();
    old.style.pointerEvents = 'none';
    anim(old, [{ transform: `translateX(${dx}px)` }, { transform: `translateX(${-d * W}px)` }], { duration: 440, easing: E.scene, fill: 'forwards' }).then(() => old.remove());
    anim(nw, [{ transform: `translateX(${dx + d * W}px)` }, { transform: 'none' }], { duration: 440, easing: E.scene });
    old.style.transform = ''; nw.style.transform = '';
    run();
  };

  cur = make(i);
  stage.append(cur);
  ENTRY.append(el);
  const back = document.activeElement;
  sync();
  x.focus({ preventScroll: true });

  // ── fly out of the cell: from the crop the cell shows to the whole picture ──
  if (cell && !reduced) {
    const m = pic();
    let flown = false;
    m.style.opacity = '0';
    const fly = () => {
      if (flown || closed) return;
      flown = true;
      m.style.opacity = '';
      out = true;
      if (m !== pic()) return hole(i);
      const a = cell.getBoundingClientRect(), b = m.getBoundingClientRect();
      hole(i);
      if (!a.width || !b.width) return;
      const s = Math.max(a.width / b.width, a.height / b.height);
      anim(m, [{ transform: tfm(b, a, s), clipPath: crop(a, b, s, radOf(cell)) }, { transform: 'none', clipPath: crop(b, b, 1, 0) }], { duration: 620, easing: E.scene });
      run();
    };
    if (m.tagName === 'IMG' && !m.complete) m.addEventListener('load', fly, { once: true });
    else if (m.tagName === 'VIDEO' && !m.videoWidth) m.addEventListener('loadedmetadata', fly, { once: true });
    else requestAnimationFrame(fly);
    setTimeout(fly, 700);
    anim(shade, [{ opacity: 0 }, { opacity: 1 }], { duration: 420, easing: E.out });
    setTimeout(() => { if (!closed) el.classList.remove('quiet'); }, 260);
  } else {
    out = true; hole(i); run();
    requestAnimationFrame(() => el.classList.remove('quiet'));
  }

  const close = quick => {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey, true);
    clearTimeout(tapT);
    if (mn) mn.vw = null;
    const fin = () => { el.remove(); hole(-1); if (back && back.isConnected && back.focus) back.focus({ preventScroll: true }); };
    if (quick || reduced) return fin();
    const m = pic(), src = cellAt(i), a = src && src.isConnected ? src.getBoundingClientRect() : null;
    el.classList.add('quiet');
    el.style.pointerEvents = 'none';
    if (m && m.tagName === 'VIDEO') { m.pause(); m.controls = false; }
    // back into the cell of the picture on screen, if that cell is in view
    if (m && a && a.width && a.bottom > 0 && a.top < innerHeight) {
      const r0 = m.getBoundingClientRect(), dim = getComputedStyle(shade).opacity;
      [cur, m, shade].forEach(n => n.getAnimations().forEach(q => q.cancel()));
      cur.style.transform = ''; m.style.transform = '';
      const b = m.getBoundingClientRect(), s = Math.max(a.width / b.width, a.height / b.height);
      anim(shade, [{ opacity: dim }, { opacity: 0 }], { duration: 420, easing: E.out, fill: 'forwards' });
      return anim(m, [{ transform: tfm(b, r0, r0.width / b.width), clipPath: crop(b, b, 1, 0) }, { transform: tfm(b, a, s), clipPath: crop(a, b, s, radOf(src)) }],
        { duration: 460, easing: E.scene, fill: 'forwards' }).then(fin);
    }
    if (m) anim(m, [{ opacity: 1 }, { opacity: 0 }], { duration: 220, easing: E.out, fill: 'forwards' });
    anim(el, [{ opacity: 1 }, { opacity: 0 }], { duration: 260, easing: E.out, fill: 'forwards' }).then(fin);
  };

  const onKey = e => {
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(); }
    else if (e.key === 'ArrowLeft') show(i - 1);
    else if (e.key === 'ArrowRight') show(i + 1);
    else if (e.key === '+' || e.key === '=') zoomTo(z.s * 1.6);
    else if (e.key === '-') zoomTo(z.s / 1.6);
    else if (e.key === '0') zoomTo(1);
    else if (e.key === 'Tab') {
      el.classList.remove('quiet');
      const f = [zb, x, p, nx, ...thumbs].filter(b => !b.hidden), k = f.indexOf(document.activeElement);
      e.preventDefault();
      f[(k + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
    }
  };
  document.addEventListener('keydown', onKey, true);
  x.addEventListener('click', () => close());
  p.addEventListener('click', () => show(i - 1));
  nx.addEventListener('click', () => show(i + 1));
  zb.addEventListener('click', () => zoomTo(z.s > 1 ? 1 : 2.5));

  // ── pointers: one finger pans a zoomed picture, pages sideways or pulls down to close; two fingers pinch ──
  const settle = () => { if (peek) { peek.el.remove(); peek = null; } cur.style.transform = ''; shade.style.opacity = ''; };
  const span = () => { const [a, b] = [...pts.values()]; return { d: Math.hypot(a.x - b.x, a.y - b.y) || 1, x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 }; };
  stage.addEventListener('dragstart', e => e.preventDefault());
  stage.addEventListener('wheel', e => { e.preventDefault(); zoomAt(e.clientX, e.clientY, z.s * Math.exp(-(e.deltaMode ? e.deltaY * 32 : e.deltaY) * 0.002)); }, { passive: false });
  stage.addEventListener('pointerdown', e => {
    if (closed || e.target.tagName === 'VIDEO' || (e.pointerType === 'mouse' && e.button !== 0)) return;
    try { stage.setPointerCapture(e.pointerId); } catch (err) { /* the pointer is already gone */ }
    pts.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pts.size === 2) { if (g && g.quiet === false) el.classList.remove('quiet'); settle(); g = { k: 'pinch', d: span().d, s: z.s }; }
    else if (pts.size === 1) g = { k: z.s > 1 ? 'pan' : '', x: e.clientX, y: e.clientY, zx: z.x, zy: z.y, at: performance.now(), moved: false, onPic: e.target === pic(), dx: 0, dy: 0 };
  });
  stage.addEventListener('pointermove', e => {
    const q = pts.get(e.pointerId);
    if (!q || !g) return;
    q.x = e.clientX; q.y = e.clientY;
    if (g.k === 'pinch') { if (pts.size > 1) { const c = span(); zoomAt(c.x, c.y, g.s * c.d / g.d); } return; }
    if (g.k === 'done') return;
    const dx = e.clientX - g.x, dy = e.clientY - g.y;
    if (!g.moved && Math.hypot(dx, dy) < 6) return;
    g.moved = true;
    if (g.k === 'pan') {
      const m = pic(), mx = Math.max(0, (m.offsetWidth * z.s - stage.clientWidth) / 2), my = Math.max(0, (m.offsetHeight * z.s - stage.clientHeight) / 2);
      z.x = lim(g.zx + dx, -mx, mx); z.y = lim(g.zy + dy, -my, my);
      return apply();
    }
    if (!g.k) {
      g.k = Math.abs(dy) > Math.abs(dx) && dy > 0 ? 'down' : 'side';
      if (g.k === 'down') { g.quiet = el.classList.contains('quiet'); el.classList.add('quiet'); }
    }
    if (g.k === 'down') {
      const k = lim(dy, 0, 320);
      g.dy = dy;
      cur.style.transform = `translateY(${Math.max(dy, 0)}px) scale(${1 - k / 1300})`;
      shade.style.opacity = String(1 - k / 420);
      return;
    }
    const d = dx < 0 ? 1 : -1, j = i + d, W = stage.clientWidth + 24;
    if (j < 0 || j >= items.length) {
      // nothing on that side: the picture resists
      if (peek) { peek.el.remove(); peek = null; }
      g.dx = dx * 0.3;
      cur.style.transform = `translateX(${g.dx}px)`;
      return;
    }
    if (!peek || peek.j !== j) { if (peek) peek.el.remove(); peek = { j, d, el: make(j) }; stage.append(peek.el); }
    g.dx = dx;
    cur.style.transform = `translateX(${dx}px)`;
    peek.el.style.transform = `translateX(${dx + d * W}px)`;
  });
  const tap = (e, q) => {
    const now = performance.now();
    if (e.pointerType === 'mouse' && !q.onPic) { if (z.s === 1) close(); return; }
    if (q.onPic && now - lastTap.at < 320 && Math.hypot(e.clientX - lastTap.x, e.clientY - lastTap.y) < 32) {
      clearTimeout(tapT); lastTap.at = 0;
      return zoomTo(z.s > 1 ? 1 : 2.5, e.clientX, e.clientY);
    }
    lastTap = { at: now, x: e.clientX, y: e.clientY };
    if (e.pointerType !== 'mouse') { clearTimeout(tapT); tapT = setTimeout(() => el.classList.toggle('quiet'), 320); }
  };
  const lift = e => {
    if (!pts.delete(e.pointerId) || !g) return;
    if (g.k === 'pinch') {
      if (pts.size === 1) { const [a] = [...pts.values()]; g = { k: z.s > 1 ? 'pan' : 'done', x: a.x, y: a.y, zx: z.x, zy: z.y, moved: true }; }
      else g = null;
      return;
    }
    const q = g;
    g = null;
    if (closed) return;
    if (!q.moved) { if (e.type === 'pointerup') tap(e, q); return; }
    if (q.k === 'down') {
      if (q.dy > 110 && e.type === 'pointerup') return close();
      anim(cur, [{ transform: cur.style.transform || 'none' }, { transform: 'none' }], { duration: 360, easing: E.back });
      anim(shade, [{ opacity: shade.style.opacity || 1 }, { opacity: 1 }], { duration: 260, easing: E.out });
      cur.style.transform = ''; shade.style.opacity = '';
      el.classList.toggle('quiet', !!q.quiet);
      return;
    }
    if (q.k !== 'side') return;
    const dx = q.dx, fast = Math.abs(dx) > 24 && Math.abs(dx) / Math.max(1, performance.now() - q.at) > 0.5;
    if (peek && e.type === 'pointerup' && (Math.abs(dx) > 70 || fast)) { cur.style.transform = ''; return show(peek.j, dx); }
    const pk = peek;
    peek = null;
    anim(cur, [{ transform: `translateX(${dx}px)` }, { transform: 'none' }], { duration: 380, easing: E.scene });
    cur.style.transform = '';
    if (pk) anim(pk.el, [{ transform: pk.el.style.transform || 'none' }, { transform: `translateX(${pk.d * (stage.clientWidth + 24)}px)` }], { duration: 320, easing: E.out, fill: 'forwards' }).then(() => pk.el.remove());
  };
  stage.addEventListener('pointerup', lift);
  stage.addEventListener('pointercancel', lift);
  if (mn) mn.vw = { close };
}

// bridge.js
'use strict';
/* Connects the sign-in screens to the engine. The page only shows what the engine
   reports (signed in or not, busy, the last message) and sends the same commands as
   the old forms; nothing is checked or stored here. */
const ENTRY = document.getElementById('entry');
const ENV = { tab: 'create', wait: null, cur: null, leave: null };
let entryOn = false, booted = false, lastFlash = '';

function send(cmd, args) {
  window.ipc.postMessage(JSON.stringify({ cmd, args: args || {} }));
}

ENTRY.insertAdjacentHTML('beforeend', "<svg xmlns=\"http://www.w3.org/2000/svg\" class=\"sprite\" aria-hidden=\"true\" focusable=\"false\"><symbol id=\"i-menu\" viewBox=\"0 0 24 24\"><path d=\"M4 7h16M4 12h16M4 17h16\"/></symbol><symbol id=\"i-search\" viewBox=\"0 0 24 24\"><circle cx=\"11\" cy=\"11\" r=\"6.5\"/><path d=\"M16 16l4 4\"/></symbol><symbol id=\"i-clip\" viewBox=\"0 0 24 24\"><path d=\"M20 11.5l-8 8a5 5 0 0 1-7-7l8.5-8.5a3.3 3.3 0 0 1 4.7 4.7L9.5 17.3a1.7 1.7 0 0 1-2.4-2.4L15 7\"/></symbol><symbol id=\"i-send\" viewBox=\"0 0 24 24\"><path d=\"M5 12h14M13 6l6 6-6 6\"/></symbol><symbol id=\"i-eye\" viewBox=\"0 0 24 24\"><path d=\"M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/></symbol><symbol id=\"i-close\" viewBox=\"0 0 24 24\"><path d=\"M6 6l12 12M18 6L6 18\"/></symbol><symbol id=\"i-back\" viewBox=\"0 0 24 24\"><path d=\"M15 5l-7 7 7 7\"/></symbol><symbol id=\"i-next\" viewBox=\"0 0 24 24\"><path d=\"M9 5l7 7-7 7\"/></symbol><symbol id=\"i-chev\" viewBox=\"0 0 24 24\"><path d=\"M9.5 6l6 6-6 6\"/></symbol><symbol id=\"i-more\" viewBox=\"0 0 24 24\"><g fill=\"currentColor\" stroke=\"none\"><circle cx=\"5.5\" cy=\"12\" r=\"1.7\"/><circle cx=\"12\" cy=\"12\" r=\"1.7\"/><circle cx=\"18.5\" cy=\"12\" r=\"1.7\"/></g></symbol><symbol id=\"i-plus\" viewBox=\"0 0 24 24\"><path d=\"M12 5v14M5 12h14\"/></symbol><symbol id=\"i-lock\" viewBox=\"0 0 24 24\"><rect x=\"5\" y=\"10.5\" width=\"14\" height=\"10\" rx=\"2.5\"/><path d=\"M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3\"/></symbol><symbol id=\"i-pin\" viewBox=\"0 0 24 24\"><path d=\"M9 4h6l-1 5 3 3v1.5H7V12l3-3-1-5zM12 13.5V20\"/></symbol><symbol id=\"i-bell\" viewBox=\"0 0 24 24\"><path d=\"M6 16.5V11a6 6 0 0 1 12 0v5.5l1.5 1.5h-15zM10 20.5a2 2 0 0 0 4 0\"/></symbol><symbol id=\"i-bell-off\" viewBox=\"0 0 24 24\"><path d=\"M8 6.2A6 6 0 0 1 18 11v5.5l1.5 1.5H9M6 11v5.5L4.5 18M10 20.5a2 2 0 0 0 4 0M4 4l16 16\"/></symbol><symbol id=\"i-sound\" viewBox=\"0 0 24 24\"><path d=\"M4 9.5h3.5L12 5.5v13l-4.5-4H4z\"/><path d=\"M15.5 9a4 4 0 0 1 0 6M18 6.5a7.5 7.5 0 0 1 0 11\"/></symbol><symbol id=\"i-sound-off\" viewBox=\"0 0 24 24\"><path d=\"M4 9.5h3.5L12 5.5v13l-4.5-4H4z\"/><path d=\"M16 9.5l5 5M21 9.5l-5 5\"/></symbol><symbol id=\"i-trash\" viewBox=\"0 0 24 24\"><path d=\"M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 13h9l1-13M10 11v5.5M14 11v5.5\"/></symbol><symbol id=\"i-check\" viewBox=\"0 0 24 24\"><path d=\"M5 12.5l4.5 4.5L19 7.5\"/></symbol><symbol id=\"i-timer\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"13\" r=\"7.5\"/><path d=\"M12 9v4l2.5 2.5M9.5 3h5\"/></symbol><symbol id=\"i-info\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M12 11v5.5M12 7.7v.1\"/></symbol><symbol id=\"i-shield\" viewBox=\"0 0 24 24\"><path d=\"M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z\"/></symbol><symbol id=\"i-shield-check\" viewBox=\"0 0 24 24\"><path d=\"M12 3l7.5 3v5.5c0 4.6-3.2 8.3-7.5 9.5-4.3-1.2-7.5-4.9-7.5-9.5V6z\"/><path d=\"M8.8 12.2l2.2 2.2 4.3-4.6\"/></symbol><symbol id=\"i-key\" viewBox=\"0 0 24 24\"><circle cx=\"8\" cy=\"15\" r=\"4\"/><path d=\"M11 12l8.5-8.5M16 7l2.5 2.5M14 9l2 2\"/></symbol><symbol id=\"i-user\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"8.5\" r=\"3.8\"/><path d=\"M4.5 20c.8-3.9 3.8-6 7.5-6s6.7 2.1 7.5 6\"/></symbol><symbol id=\"i-users\" viewBox=\"0 0 24 24\"><circle cx=\"9\" cy=\"9\" r=\"3.4\"/><path d=\"M3 19.5c.6-3.4 3-5.3 6-5.3s5.4 1.9 6 5.3M15.5 5.9a3.4 3.4 0 0 1 0 6.3M17.5 14.5c1.9.6 3.1 2.3 3.5 5\"/></symbol><symbol id=\"i-channel\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"1.8\"/><path d=\"M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.6 5.6a9 9 0 0 0 0 12.8M18.4 5.6a9 9 0 0 1 0 12.8\"/></symbol><symbol id=\"i-link\" viewBox=\"0 0 24 24\"><path d=\"M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1\"/></symbol><symbol id=\"i-copy\" viewBox=\"0 0 24 24\"><rect x=\"8.5\" y=\"8.5\" width=\"11\" height=\"11\" rx=\"2.5\"/><path d=\"M15.5 8.5V6A1.5 1.5 0 0 0 14 4.5H6A1.5 1.5 0 0 0 4.5 6v8A1.5 1.5 0 0 0 6 15.5h2.5\"/></symbol><symbol id=\"i-refresh\" viewBox=\"0 0 24 24\"><path d=\"M19.5 12a7.5 7.5 0 1 1-2.2-5.3M19.5 4.5v4h-4\"/></symbol><symbol id=\"i-leave\" viewBox=\"0 0 24 24\"><path d=\"M14 4.5H6.5A1.5 1.5 0 0 0 5 6v12a1.5 1.5 0 0 0 1.5 1.5H14M10.5 12H20M16.5 8.5L20 12l-3.5 3.5\"/></symbol><symbol id=\"i-image\" viewBox=\"0 0 24 24\"><rect x=\"3.5\" y=\"5\" width=\"17\" height=\"14\" rx=\"2.5\"/><circle cx=\"9\" cy=\"10\" r=\"1.6\"/><path d=\"M20.5 15.5L16 11l-8 8\"/></symbol><symbol id=\"i-video\" viewBox=\"0 0 24 24\"><rect x=\"3.5\" y=\"6\" width=\"12\" height=\"12\" rx=\"2.5\"/><path d=\"M15.5 10.5l5-3v9l-5-3\"/></symbol><symbol id=\"i-play\" viewBox=\"0 0 24 24\"><path d=\"M8 5.5v13l10.5-6.5z\" fill=\"currentColor\" stroke=\"none\"/></symbol><symbol id=\"i-sliders\" viewBox=\"0 0 24 24\"><path d=\"M4 7h10M18 7h2M4 17h4M12 17h8\"/><circle cx=\"16\" cy=\"7\" r=\"2\"/><circle cx=\"10\" cy=\"17\" r=\"2\"/></symbol><symbol id=\"i-globe\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M3.5 12h17M12 3.5c2.4 2.4 3.5 5.2 3.5 8.5s-1.1 6.1-3.5 8.5c-2.4-2.4-3.5-5.2-3.5-8.5s1.1-6.1 3.5-8.5z\"/></symbol><symbol id=\"i-spark\" viewBox=\"0 0 24 24\"><path d=\"M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5L18 18M18 6l-2.5 2.5M8.5 15.5L6 18\"/></symbol><symbol id=\"i-archive\" viewBox=\"0 0 24 24\"><rect x=\"3.5\" y=\"4.5\" width=\"17\" height=\"4.5\" rx=\"1.5\"/><path d=\"M5 9v9.5A1.5 1.5 0 0 0 6.5 20h11a1.5 1.5 0 0 0 1.5-1.5V9M10 13h4\"/></symbol><symbol id=\"i-backspace\" viewBox=\"0 0 24 24\"><path d=\"M9 5.5h10.5A1.5 1.5 0 0 1 21 7v10a1.5 1.5 0 0 1-1.5 1.5H9L3 12z\"/><path d=\"M12 9.5l5 5M17 9.5l-5 5\"/></symbol><symbol id=\"i-onion\" viewBox=\"0 0 24 24\"><path d=\"M12 3.5c.4 2.6 6 5 6 10a6 6 0 0 1-12 0c0-5 5.6-7.4 6-10z\"/><path d=\"M12 8c-.2 2-3 3.4-3 6a3 3 0 0 0 6 0c0-2.6-2.8-4-3-6z\"/></symbol><symbol id=\"i-at\" viewBox=\"0 0 24 24\"><circle cx=\"12\" cy=\"12\" r=\"3.5\"/><path d=\"M15.5 12v1.5a2.5 2.5 0 0 0 5 0V12a8.5 8.5 0 1 0-3.3 6.7\"/></symbol><symbol id=\"i-fingerprint\" viewBox=\"0 0 24 24\"><path d=\"M7.5 18.5c1-2 1.5-4 1.5-6.5a3 3 0 0 1 6 0c0 2.5-.3 4.5-1 6.5M12 12c0 3-.6 5.5-2 8M5 15c.3-1 .5-2 .5-3a6.5 6.5 0 0 1 13 0c0 1.5-.1 3-.4 4.3M6.5 6.5A8.5 8.5 0 0 1 19 7.5\"/></symbol><symbol id=\"i-warn\" viewBox=\"0 0 24 24\"><path d=\"M12 4l9 16H3z\"/><path d=\"M12 10v4.5M12 17.2v.1\"/></symbol><symbol id=\"i-zoom\" viewBox=\"0 0 24 24\"><circle cx=\"11\" cy=\"11\" r=\"6.5\"/><path d=\"M16 16l4 4M11 8.5v5M8.5 11h5\"/></symbol><symbol id=\"i-zoomout\" viewBox=\"0 0 24 24\"><circle cx=\"11\" cy=\"11\" r=\"6.5\"/><path d=\"M16 16l4 4M8.5 11h5\"/></symbol><symbol id=\"i-frame\" viewBox=\"0 0 24 24\"><path d=\"M4 9V5.5A1.5 1.5 0 0 1 5.5 4H9M15 4h3.5A1.5 1.5 0 0 1 20 5.5V9M20 15v3.5a1.5 1.5 0 0 1-1.5 1.5H15M9 20H5.5A1.5 1.5 0 0 1 4 18.5V15\"/></symbol></svg>");

// ENV.leave: the gate is done, the messenger shows through as the entry fades out
ENV.leave = () => {
  if (!entryOn) return;
  if (S.acct) { AegisScene.rest(700); go('main', { tr: 'zoom' }); return; }
  entryOn = false;
  ENV.wait = null;
  AegisScene.rest(700);
  anim(ENTRY, [{ opacity: 1, transform: 'none' }, { opacity: 0, transform: 'scale(1.04)' }], { duration: reduced ? 1 : 520, easing: E.scene, fill: 'forwards' })
    .then(() => {
      if (entryOn) return;
      ENTRY.hidden = true;
      ENTRY.getAnimations().forEach(a => a.cancel());
      if (curScr) { curScr._off && curScr._off(); curScr.remove(); curScr = null; scrName = ''; }
    });
};

const SCREENS = { splash: () => scrSplash(), onb: () => scrOnb(), auth: o => scrAuth(o), gate: o => scrGate(o), lock: o => scrLock(o), main: o => scrMain(o) };
let curScr = null, scrName = '';
// a locked account with a PIN gets the keypad, everything else the sign-in tabs
const authScr = () => (ENV.lock && ENV.lock.user ? 'lock' : 'auth');
function go(name, o = {}) {
  const app = $('#app');
  const prev = curScr;
  const next = SCREENS[name](o);
  next.classList.add('scr');
  next.dataset.scr = name;
  curScr = next; scrName = name;
  if (prev) { prev._off && prev._off(); prev.inert = true; }
  app.append(next);
  const tr = prev ? o.tr || 'fade' : 'none';
  const D = { duration: 560, easing: E.scene, fill: 'both' };
  let out = Promise.resolve();
  if (tr === 'push' || tr === 'back') {
    const s = tr === 'push' ? 1 : -1;
    anim(next, [{ transform: `translateX(${s * 100}%)` }, { transform: 'none' }], D);
    out = anim(prev, [{ transform: 'none', opacity: 1 }, { transform: `translateX(${-s * 24}%)`, opacity: 0.3 }], D);
  } else if (tr === 'zoom') {
    anim(next, [{ transform: 'scale(.94)', opacity: 0 }, { transform: 'none', opacity: 1 }], { ...D, duration: 700 });
    out = anim(prev, [{ transform: 'none', opacity: 1 }, { transform: 'scale(1.06)', opacity: 0 }], { ...D, duration: 500 });
  } else if (tr === 'fade') {
    anim(next, [{ opacity: 0 }, { opacity: 1 }], { duration: 420, easing: E.out, fill: 'both' });
    out = anim(prev, [{ opacity: 1 }, { opacity: 0 }], { duration: 300, easing: E.out, fill: 'both' });
  }
  next._enter && next._enter();
  if (prev) out.then(() => prev.remove());
}

function entryUpdate(s) {
  if (s.lang && s.lang !== LANG) {
    LANG = s.lang === 'en' ? 'en' : 'ru';
    try { localStorage.setItem('aegis.lang', LANG); } catch (e) { /* private mode */ }
    if (entryOn && scrName === 'auth' && !ENV.wait) go('auth', { tr: 'none', tab: ENV.cur ? ENV.cur() : ENV.tab });
  }
  ENV.tab = s.tab || ENV.tab;
  if (!s.authed) ENV.lock = s.lock || null;
  if (s.authed && s.m) {
    const sh = document.getElementById('shell');
    if (sh) sh.hidden = true;
    eng.update(s);
    if (!entryOn) { entryOn = true; booted = true; ENTRY.hidden = false; ENTRY.getAnimations().forEach(a => a.cancel()); go('main', { tr: 'fade' }); return; }
    if (scrName === 'main') return;
    lastFlash = s.flash ? JSON.stringify(s.flash) : '';
  } else if (scrName === 'main') {
    S.acct = null; eng.m = null; lookApply(null);
    $$('.scrim, .sheet, .menu', ENTRY).forEach(x => x.remove());
    go(authScr(), { tr: 'fade' });
  }
  const f = s.flash;
  const fk = f ? JSON.stringify(f) : '';
  if (fk !== lastFlash) {
    lastFlash = fk;
    if (f && !s.authed && entryOn) {
      const w = ENV.wait;
      ENV.wait = null;
      if (!f.ok && w) w.fail(f.text); else flash(f.text, f.ok ? 'ok' : 'err');
      send('dismiss_flash');
    }
  }
  if (!s.authed) {
    if (!entryOn) {
      entryOn = true;
      ENTRY.hidden = false;
      ENTRY.getAnimations().forEach(a => a.cancel());
      document.documentElement.lang = LANG;
      go(booted ? authScr() : 'splash', { tr: 'fade' });
      booted = true;
    }
    return;
  }
  booted = true;
  if (!entryOn) return;
  const w = ENV.wait;
  ENV.wait = null;
  if (scrName === 'gate' && w && w.ok) w.ok();
  else if (scrName === 'auth' || scrName === 'lock') go('gate', { acct: { username: (w && w.user) || '' }, tr: 'push' });
  else ENV.leave();
}

window.aegisEntry = {
  update: entryUpdate,
  inChat: () => !!(mn && mn.chat),
  layered: () => !!((mn && (mn.chat || mn.sec || mn.info)) || openSheets.length || openMenu),
};

})();

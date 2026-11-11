'use strict';
(() => {
// core.js
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
const I18N = {"auth.tagline":["No phone number, no email, no real name. A username and a password are enough.","Без номера телефона, почты и настоящего имени. Достаточно ника и пароля."],"auth.eyebrow":["PRIVATE BY DEFAULT","ПРИВАТНО ПО УМОЛЧАНИЮ"],"auth.chip1":["end-to-end encrypted","сквозное шифрование"],"auth.chip2":["no phone, no email","без телефона и почты"],"auth.chip3":["open source","открытый код"],"auth.foot":["Your boundaries. Your keys.","Ваши границы. Ваши ключи."],"auth.headline":["Everyone has a right to a private space.","У каждого есть право на личное пространство."],"auth.pwnote":["The password cannot be recovered. The server never receives it.","Пароль не восстанавливается. Сервер его никогда не получает."],"chat.hint":["End-to-end encrypted. The server sees only the queue and the time.","Сквозное шифрование. Сервер видит только очередь и время."],"contact.key_verified":["key verified","ключ проверен"],"ttl.short":["disappearing","исчезают"],"status.online":["Connected","Подключено"],"status.offline":["No connection","Нет соединения"],"status.connecting":["Connecting","Подключение"],"auth.tab_unlock":["Unlock","Войти"],"auth.tab_create":["Create","Создать"],"auth.tab_import":["Import","Импорт"],"auth.unlock":["Unlock","Войти"],"auth.create":["Create account","Создать аккаунт"],"auth.import":["Import","Импортировать"],"auth.import_note":["Enter the full path of a vault file exported from Aegis. It is decrypted first and only then copied into the data folder.","Укажите полный путь к файлу, экспортированному из Aegis. Сначала он расшифровывается и только потом копируется в папку данных."],"f.username":["Username","Ник"],"f.username_new":["Username (a-z, 0-9, _)","Ник (a-z, 0-9, _)"],"f.display":["Display name","Отображаемое имя"],"f.password":["Password","Пароль"],"f.password_new":["Password (10+ characters)","Пароль (от 10 символов)"],"f.confirm":["Repeat password","Повторите пароль"],"f.vault_path":["Vault file path","Путь к файлу"],"f.contact_username":["Username","Ник"],"f.group_title":["Group name","Название группы"],"f.endpoint":["Server address","Адрес сервера"],"f.socks5":["SOCKS5 proxy (host:port, optional)","SOCKS5-прокси (host:port, необязательно)"],"f.idle":["Lock after idle minutes (0 = never)","Блокировать после простоя, минут (0 — никогда)"],"f.export_path":["Full path for the exported file","Полный путь для файла экспорта"],"f.confirm_name":["Type your username to confirm","Введите свой ник для подтверждения"],"nav.settings":["Settings","Настройки"],"nav.lock":["Lock","Заблокировать"],"nav.new_chat":["New chat","Новый чат"],"nav.new_group":["New group","Новая группа"],"list.empty":["No chats yet. Start one with a username.","Чатов пока нет. Начните с ника собеседника."],"list.filter":["Filter chats","Фильтр чатов"],"main.welcome_title":["Aegis","Aegis"],"main.pick":["Select a chat or start a new one.","Выберите чат или начните новый."],"main.e2ee":["Messages are end-to-end encrypted. The server sees which queue receives a message and when, not its contents.","Сообщения шифруются сквозным шифрованием. Сервер видит, в какую очередь и когда пришло сообщение, но не его содержимое."],"chat.placeholder":["Message","Сообщение"],"chat.send":["Send","Отправить"],"chat.empty":["No messages yet.","Сообщений пока нет."],"chat.ttl_on":["Disappearing messages are on. New messages are deleted on both devices when the timer ends, counted from when each device got them.","Исчезающие сообщения включены. Новые сообщения удаляются на обоих устройствах по истечении таймера, который отсчитывается с момента получения."],"msg.sending":["sending...","отправка..."],"msg.failed":["not sent","не отправлено"],"msg.retry":["Retry","Повторить"],"ttl.label":["Disappearing messages","Исчезающие сообщения"],"ttl.off":["Off","Выкл"],"ttl.30s":["30 seconds","30 секунд"],"ttl.5m":["5 minutes","5 минут"],"ttl.1h":["1 hour","1 час"],"ttl.1d":["1 day","1 день"],"ttl.7d":["1 week","1 неделя"],"ttl.you":["You","Вы"],"warn.key_changed":["The keys of","Ключи контакта"],"warn.compare":["have changed. Messages signed with the new keys are not shown until you accept them. Compare the safety number with your contact first.","изменились. Сообщения с новыми ключами не показываются, пока вы их не примете. Сначала сверьте номер безопасности с собеседником."],"warn.group_only":["differ from the pinned ones in a group message. The message was dropped. Keys can only be accepted from a direct message.","в групповом сообщении отличаются от сохранённых. Сообщение отброшено. Принять новые ключи можно только из личного сообщения."],"warn.view":["Safety number","Номер безопасности"],"warn.accept":["Accept new key","Принять новый ключ"],"warn.dismiss":["Dismiss","Скрыть"],"contact.title":["Contact","Контакт"],"contact.verified":["verified","проверен"],"contact.unverified":["not verified","не проверен"],"contact.safety":["Safety number","Номер безопасности"],"contact.safety_note":["Compare these numbers with your contact over another channel. If they match, nobody replaced the keys between you.","Сверьте эти числа с собеседником по другому каналу. Если они совпали, ключи по дороге никто не подменил."],"contact.mark_verified":["Mark as verified","Отметить как проверенный"],"contact.delete":["Delete chat and contact","Удалить чат и контакт"],"newchat.note":["Enter the exact username of the person. Users cannot be searched. The server returns the public keys registered under that name, and they are pinned on first use.","Введите точный ник человека. Поиска пользователей нет. Сервер возвращает публичные ключи, зарегистрированные под этим ником, и они запоминаются при первом использовании."],"newchat.add":["Start chat","Начать чат"],"inv.title":["Invite link","Ссылка-приглашение"],"inv.note":["A link works once and for 7 days. Whoever opens it gets your keys directly, without a directory lookup. Share it only with the person you mean.","Ссылка срабатывает один раз и действует 7 дней. Открывший её получает ваши ключи напрямую, без запроса к каталогу. Передавайте её только тому, кому она предназначена."],"inv.create":["Create invite","Создать приглашение"],"inv.another":["Create another","Создать ещё"],"inv.copy":["Copy","Копировать"],"inv.open_title":["Open an invite","Открыть приглашение"],"inv.open_note":["Paste an aegis://invite/ link someone gave you.","Вставьте ссылку aegis://invite/, которую вам дали."],"inv.open":["Open","Открыть"],"f.invite_link":["Invite link","Ссылка-приглашение"],"busy.invite":["Talking to the server...","Связь с сервером..."],"err.invite_limit":["Too many open invites. Wait until some are used or expire.","Слишком много открытых приглашений. Дождитесь, пока часть будет использована или истечёт."],"err.invite_link":["This is not an invite link.","Это не ссылка-приглашение."],"err.invite_gone":["This invite was already used, has expired or does not exist.","Приглашение уже использовано, истекло или не существует."],"err.invite_conflict":["A contact with this name or these keys already exists with other keys. The invite was not applied.","Контакт с этим ником или этими ключами уже есть, но с другими ключами. Приглашение не применено."],"newgroup.note":["Up to 100 members including you. Only existing contacts can be added. Every member receives the group key in a direct message.","До 100 участников включая вас. Добавить можно только существующих контактов. Каждый участник получает ключ группы в личном сообщении."],"newgroup.members":["Members","Участники"],"newgroup.no_contacts":["Add contacts first.","Сначала добавьте контакты."],"newgroup.create":["Create group","Создать группу"],"group.info":["Group","Группа"],"group.members_n":["members","участников"],"group.you":["you","вы"],"group.creator":["creator","создатель"],"group.resend":["Resend invite","Отправить приглашение снова"],"group.leave":["Leave group","Покинуть группу"],"group.leave_note":["Leaving deletes the group from this device only. The other members keep the group key and can still read what they receive.","Выход удаляет группу только на этом устройстве. У остальных участников ключ группы остаётся, и они продолжают читать свои сообщения."],"dlg.delete_chat":["Delete chat","Удалить чат"],"dlg.delete_chat_text":["This removes the chat and the pinned keys of","Будут удалены чат и сохранённые ключи контакта"],"dlg.delete_account_text":["This deletes the vault file on this device. Without an exported copy the account cannot be restored. Type","Будет удалён файл хранилища на этом устройстве. Без экспортированной копии аккаунт не восстановить. Введите"],"common.back":["Back","Назад"],"common.cancel":["Cancel","Отмена"],"common.close":["Close","Закрыть"],"common.save":["Save","Сохранить"],"set.profile":["Profile","Профиль"],"set.connection":["Connection and lock","Соединение и блокировка"],"set.conn_note":["The default address is behind Cloudflare. TLS ends there, so Cloudflare can see your IP address and when you connect, but not message contents. A SOCKS5 proxy hides your address from the server operator and Cloudflare. Names are resolved through the proxy.","Адрес по умолчанию стоит за Cloudflare. TLS заканчивается там, поэтому Cloudflare видит ваш IP-адрес и время подключений, но не содержимое сообщений. SOCKS5-прокси скрывает ваш адрес от оператора сервера и Cloudflare. Имена разрешаются через прокси."],"set.flash":["Flash the taskbar on new messages (no message text is shown)","Мигать на панели задач при новых сообщениях (текст не показывается)"],"set.test":["Test connection","Проверить соединение"],"set.language":["Language","Язык"],"set.lang_note":["Takes effect immediately.","Применяется сразу."],"set.backup":["Backup","Резервная копия"],"set.backup_note":["Export copies the encrypted vault file to the path you give. It is protected by your password. Existing files are not overwritten.","Экспорт копирует зашифрованный файл хранилища по указанному пути. Он защищён вашим паролем. Существующие файлы не перезаписываются."],"set.export":["Export vault","Экспортировать"],"set.danger":["Delete account data","Удаление данных аккаунта"],"set.delete_note":["Deletes the vault file on this device only. The name stays registered on the server and cannot be reused.","Удаляет только файл хранилища на этом устройстве. Ник остаётся занят на сервере и не может быть использован снова."],"set.delete":["Delete account data on this device","Удалить данные аккаунта на этом устройстве"],"set.about":["About","О программе"],"set.about_text":["Aegis is an experimental end-to-end encrypted messenger. The protocol and the source code are public.","Aegis — экспериментальный мессенджер со сквозным шифрованием. Протокол и исходный код открыты."],"set.about_font":["Interface fonts: Geist and Geist Mono, SIL Open Font License 1.1.","Шрифты интерфейса: Geist и Geist Mono, лицензия SIL Open Font License 1.1."],"conn.running":["Testing...","Проверка..."],"conn.ok":["The server answered.","Сервер ответил."],"busy.create":["Creating account: generating keys and solving the registration puzzle...","Создание аккаунта: генерация ключей и решение задачи регистрации..."],"busy.unlock":["Unlocking...","Вход..."],"busy.lookup":["Looking up the user...","Поиск пользователя..."],"busy.group":["Creating group and sending invites...","Создание группы и отправка приглашений..."],"busy.profile":["Saving profile...","Сохранение профиля..."],"ok.saved":["Saved.","Сохранено."],"ok.exported":["Exported to","Экспортировано в"],"ok.deleted":["Account data deleted from this device.","Данные аккаунта удалены с этого устройства."],"ok.invite_sent":["Invite sent to","Приглашение отправлено:"],"err.generic":["Something went wrong.","Что-то пошло не так."],"err.taken":["This username is already taken.","Этот ник уже занят."],"err.queue_full":["The server refused the request: rate limit or full queue. Try again later.","Сервер отклонил запрос: лимит или переполненная очередь. Повторите позже."],"err.rejected":["The server rejected the request.","Сервер отклонил запрос."],"err.network":["Could not reach the server.","Не удалось связаться с сервером."],"err.password":["Wrong password or damaged vault file.","Неверный пароль или повреждённый файл."],"err.username":["Invalid username.","Недопустимый ник."],"err.endpoint":["Invalid server address.","Недопустимый адрес сервера."],"err.too_long":["The message is too long.","Сообщение слишком длинное."],"err.confirm":["The passwords do not match.","Пароли не совпадают."],"err.confirm_name":["The username does not match.","Ник не совпадает."],"err.password_short":["The password must have at least 10 characters.","Пароль должен содержать не меньше 10 символов."],"err.display":["Invalid display name (1 to 64 characters).","Недопустимое имя (от 1 до 64 символов)."],"err.exists":["An account with this name already exists on this device.","Аккаунт с таким ником уже есть на этом устройстве."],"err.file_exists":["The file already exists. Choose another path.","Файл уже существует. Выберите другой путь."],"err.path":["Enter a full path in an existing folder.","Укажите полный путь в существующей папке."],"err.no_account":["No account with this username on this device.","На этом устройстве нет аккаунта с таким ником."],"err.vault_format":["The file is not a valid Aegis vault.","Файл не является хранилищем Aegis."],"err.disk":["Could not read or write the file.","Не удалось прочитать или записать файл."],"err.locked":["Not unlocked.","Хранилище заблокировано."],"err.self":["That is your own username.","Это ваш собственный ник."],"err.not_found":["No user with this username on the server.","Пользователь с таким ником на сервере не найден."],"err.empty":["The message is empty.","Сообщение пустое."],"err.no_contact":["Unknown contact.","Неизвестный контакт."],"err.no_group":["Unknown group.","Неизвестная группа."],"err.group_title":["Enter a group name.","Введите название группы."],"err.group_members":["Select at least one member.","Выберите хотя бы одного участника."],"err.group_big":["A group can have at most 100 members including you.","В группе не больше 100 участников, включая вас."],"err.invite_failed":["The group was created, but these invites were not delivered. Resend them from the group page:","Группа создана, но приглашения не доставлены. Отправьте их снова на странице группы:"],"err.socks":["The proxy must look like host:port.","Прокси должен иметь вид host:port."],"tab.all":["All","Все"],"tab.groups":["Groups","Группы"],"tab.channels":["Channels","Каналы"],"drawer.account":["Settings","Настройки"],"nav.new_channel":["New channel","Новый канал"],"nav.contacts":["Contacts","Контакты"],"list.you":["You:","Вы:"],"list.lookup":["Search the server for","Искать на сервере:"],"media.photo":["Photo","Фото"],"media.video":["Video","Видео"],"chan.official":["Official channel","Официальный канал"],"chan.channel":["Channel","Канал"],"chan.subs_n":["subscribers","подписчиков"],"chan.official_tag":["official","официальный"],"chan.manage":["Channel","Канал"],"chan.invite":["Invite selected","Пригласить выбранных"],"chan.delete":["Delete channel","Удалить канал"],"chan.leave":["Leave channel","Покинуть канал"],"chan.leave_note":["The channel is removed from this device only. Posts you already received stay with the other subscribers.","Канал будет удалён только на этом устройстве. У остальных подписчиков полученные записи останутся."],"chan.key_changed":["The key of the channel owner differs from the saved one. New posts are not shown.","Ключ владельца канала отличается от сохранённого. Новые записи не показываются."],"menu.info":["Info","Информация"],"menu.pin":["Pin","Закрепить"],"menu.unpin":["Unpin","Открепить"],"menu.mute":["Mute","Выключить уведомления"],"menu.unmute":["Unmute","Включить уведомления"],"menu.clear":["Clear history","Очистить историю"],"menu.more":["More","Ещё"],"chat.search":["Search in chat","Поиск в чате"],"chat.attach":["Attach a photo or video","Прикрепить фото или видео"],"info.media":["Shared media","Медиа"],"newchannel.note":["Anyone you invite can read what you post. Subscribers cannot write. Up to 200 subscribers.","Приглашённые читают ваши записи, но писать не могут. До 200 подписчиков."],"newchannel.create":["Create channel","Создать канал"],"f.channel_title":["Channel name","Название канала"],"f.about":["About (up to 140 characters)","О себе (до 140 символов)"],"f.particles":["Particles","Частицы"],"contacts.chat":["Chat","Чат"],"acct.profile":["Account","Аккаунт"],"acct.privacy":["Security and privacy","Безопасность и приватность"],"acct.notifications":["Notifications","Уведомления"],"acct.appearance":["Appearance","Оформление"],"acct.connection":["Network and Tor","Сеть и Tor"],"acct.data":["Backup and deletion","Копия и удаление"],"pfx.none":["None","Нет"],"pfx.dust":["Dust","Пыль"],"pfx.snow":["Snow","Снег"],"pfx.embers":["Embers","Угли"],"pfx.orbit":["Orbit","Орбита"],"pfx.rain":["Rain","Дождь"],"profile.note":["Your name and about line are sent to your contacts.","Имя и строка о себе отправляются вашим контактам."],"priv.lock":["App lock","Блокировка приложения"],"priv.lock_min":["Also lock when the window is minimized","Блокировать и при сворачивании окна"],"priv.lock_note":["With the lock on, the app locks after the idle time above (0 turns that off) and, if chosen, when minimized. Opening the app always needs your password or PIN, because they unlock the encrypted vault.","Когда блокировка включена, приложение блокируется после указанного времени бездействия (0 отключает это) и, если выбрано, при сворачивании. Для запуска всегда нужен пароль или PIN-код: ими открывается зашифрованное хранилище."],"priv.protect":["Hide the window from screen capture","Скрывать окно от захвата экрана"],"priv.lookup":["Profile lookup","Поиск профиля"],"priv.hidden":["Hide profile","Скрыть профиль"],"priv.hidden_note":["Looking up your username then answers \"not found\". New contacts can reach you only through an invite link. Existing contacts are not affected.","Поиск по вашему нику будет отвечать «не найден». Новые контакты смогут найти вас только по ссылке-приглашению. Существующие контакты это не затронет."],"priv.protect_note":["Screenshots and screen sharing show a blank window.","На снимках и в трансляции экрана окно будет пустым."],"priv.pin":["PIN","PIN-код"],"priv.set_pin":["Set PIN","Задать PIN"],"priv.set_duress":["Set duress PIN","Задать PIN принуждения"],"priv.pin_note":["With a PIN you unlock with 4 or 6 digits instead of the password. The server counts the attempts and gives up the secret after five wrong ones. A duress PIN erases this account from the device and then shows the usual wrong-PIN message.","С PIN-кодом вы входите четырьмя или шестью цифрами вместо пароля. Сервер считает попытки и после пяти неверных перестаёт выдавать секрет. PIN принуждения стирает этот аккаунт с устройства и показывает обычное сообщение о неверном PIN."],"priv.pin_on":["A PIN is set.","PIN-код задан."],"priv.duress_on":["A duress PIN is set.","PIN принуждения задан."],"priv.remove_pin":["Remove PIN","Убрать PIN"],"priv.clear_duress":["Remove duress PIN","Убрать PIN принуждения"],"f.pin":["PIN (4 or 6 digits)","PIN (4 или 6 цифр)"],"f.pin_confirm":["Repeat the PIN","Повторите PIN"],"f.pin_current":["Current PIN","Текущий PIN"],"f.duress":["Duress PIN","PIN принуждения"],"f.secret":["Password or PIN","Пароль или PIN"],"busy.pin":["Talking to the server...","Связь с сервером..."],"ok.pin_set":["PIN set.","PIN задан."],"ok.pin_removed":["PIN removed.","PIN убран."],"ok.duress_set":["Duress PIN set.","PIN принуждения задан."],"ok.duress_cleared":["Duress PIN removed.","PIN принуждения убран."],"err.pin_format":["A PIN is 4 or 6 digits.","PIN состоит из 4 или 6 цифр."],"err.pin_mismatch":["The PINs do not match.","PIN-коды не совпадают."],"err.pin_exists":["A PIN is already set.","PIN уже задан."],"err.pin_none":["No PIN is set.","PIN не задан."],"err.pin_wrong":["Wrong PIN. Tries left","Неверный PIN. Осталось попыток"],"err.pin_throttled":["Try again in a moment.","Попробуйте через минуту."],"err.pin_gone":["This PIN no longer works. Enter your password.","Этот PIN больше не действует. Введите пароль."],"err.duress_same":["The duress PIN must differ from your PIN.","PIN принуждения должен отличаться от вашего PIN."],"notify.on":["Notify about new messages","Уведомлять о новых сообщениях"],"notify.name":["Show the sender and text in notifications","Показывать отправителя и текст в уведомлениях"],"notify.note":["When off, a notification says only New message, with no sender and no text. Nothing arrives while the app is locked. Muted chats stay silent.","Если выключено, уведомление говорит только «Новое сообщение», без отправителя и текста. Пока приложение заблокировано, уведомлений нет. Чаты без звука молчат."],"notify.new":["New message","Новое сообщение"],"conn.cover":["Cover traffic","Маскирующий трафик"],"conn.cover_note":["Cover traffic hides when you are really talking. It stops while the app is locked or minimized.","Маскирующий трафик скрывает, когда вы действительно общаетесь. Он останавливается, пока приложение заблокировано или свёрнуто."],"conn.cover_off":["Off","Выключен"],"conn.cover_std":["Standard","Обычный"],"conn.cover_high":["High","Усиленный"],"conn.tor":["Connect through Tor","Подключаться через Tor"],"conn.tor_note":["Tor is built into the app. With it on, the app reaches the server through its onion address and sends nothing until Tor is connected. The proxy field is ignored; turn Tor off to use it.","Tor встроен в приложение. Когда он включён, приложение подключается к серверу через onion-адрес и ничего не отправляет, пока Tor не подключился. Поле прокси при этом не используется; выключите Tor, чтобы им пользоваться."],"conn.tor_off":["Tor is off: the server sees your address.","Tor выключен: сервер видит ваш адрес."],"conn.tor_start":["Tor is connecting","Tor подключается"],"conn.tor_ready":["Tor is connected.","Tor подключён."],"conn.tor_failed":["Tor could not connect, retrying.","Tor не удалось подключить, повторяю попытку."],"conn.tor_bridge":["Bridges:","Мосты:"],"conn.bridges":["Tor bridges","Мосты Tor"],"conn.bridges_off":["Off","Выключены"],"conn.bridges_snowflake":["Snowflake (built-in)","Snowflake (встроенные)"],"conn.bridges_obfs4":["obfs4 (built-in)","obfs4 (встроенные)"],"conn.bridges_custom":["WebTunnel or own bridges","WebTunnel или свои мосты"],"f.bridge_lines":["Bridge lines, one per line","Строки мостов, по одной на строку"],"conn.bridges_note":["Use bridges where Tor is blocked. Snowflake works in most places; if it does not, try obfs4. For WebTunnel or private bridges get lines from bridges.torproject.org or @GetBridgesBot in Telegram and paste them here.","Мосты нужны там, где Tor заблокирован. Snowflake работает почти везде; если нет, попробуйте obfs4. Для WebTunnel или частных мостов получите строки на bridges.torproject.org или у @GetBridgesBot в Telegram и вставьте их сюда."],"err.bridge_line":["Not a bridge line, line","Это не строка моста, строка"],"err.bridges_empty":["Paste at least one bridge line.","Вставьте хотя бы одну строку моста."],"err.bridges_many":["Too many bridge lines.","Слишком много строк мостов."],"err.clearnet_tor":["This address is the clearnet entry behind Cloudflare. With Tor on the app uses the onion address of the server.","Этот адрес — вход через обычный интернет за Cloudflare. С Tor приложение использует onion-адрес сервера."],"err.tor_off_first":["Save the settings with Tor off before testing without Tor.","Сначала сохраните настройки с выключенным Tor, потом проверяйте без Tor."],"err.tor_on_first":["Save the settings with Tor on before testing through Tor, so your bridges are used.","Сначала сохраните настройки с включённым Tor, потом проверяйте через Tor, чтобы использовались ваши мосты."],"dlg.tor_off":["Turn off Tor?","Выключить Tor?"],"dlg.tor_off_text":["Without Tor your IP address becomes visible to the server and to Cloudflare, which carries the clearnet connection. Your provider also sees that you connect to Aegis.","Без Tor ваш IP-адрес становится виден серверу и Cloudflare, через который идёт подключение. Ваш провайдер тоже видит, что вы подключаетесь к Aegis."],"dlg.tor_off_ok":["Turn off Tor","Выключить Tor"],"upd.title":["Updates","Обновления"],"upd.auto":["Install updates automatically","Устанавливать обновления автоматически"],"upd.note":["Updates are signed with the Aegis release key and downloaded through the same route as messages. A verified update installs when Aegis locks or closes.","Обновления подписаны ключом выпусков Aegis и загружаются тем же маршрутом, что и сообщения. Проверенное обновление устанавливается, когда Aegis блокируется или закрывается."],"upd.version":["Version","Версия"],"upd.checking":["Checking for updates…","Проверяю обновления…"],"upd.available":["New version available:","Доступна новая версия:"],"upd.downloading":["Downloading version","Загружаю версию"],"upd.ready":["Ready to install: version","Готова к установке версия"],"upd.ready_when":["It installs when Aegis locks or closes.","Она установится, когда Aegis заблокируется или закроется."],"upd.required":["This version is no longer supported, restart to update.","Эта версия больше не поддерживается, перезапустите для обновления."],"upd.failed":["Could not check for updates.","Не удалось проверить обновления."],"upd.bad_sig":["Update refused: the signature is not valid.","Обновление отклонено: подпись недействительна."],"upd.bad_file":["Update refused: the file does not match the signed manifest.","Обновление отклонено: файл не совпадает с подписанным манифестом."],"upd.rollback":["Update refused: the server offered an older release.","Обновление отклонено: сервер предложил более старый выпуск."],"upd.check":["Check now","Проверить сейчас"],"upd.download":["Download","Загрузить"],"upd.restart":["Restart and update","Перезапустить и обновить"],"err.tor_boot":["Tor is still connecting. Nothing is sent until it is ready.","Tor ещё подключается. Пока он не готов, ничего не отправляется."],"err.server_key_changed":["The server key changed.","Ключ сервера изменился."],"err.server_key_unset":["The server key is not confirmed yet. Check the connection.","Ключ сервера ещё не подтверждён. Проверьте подключение."],"chan.official_off":["Official channel (not available yet)","Официальный канал (пока недоступен)"],"key.title":["Server key changed","Ключ сервера изменился"],"key.text":["This server now shows a different transport key than the one pinned on first use. Someone may be intercepting the connection, or the server was reinstalled. Nothing is sent or received. Lock the app and ask the server operator before continuing.","Сервер теперь показывает другой транспортный ключ, чем тот, что был запомнен при первом подключении. Возможно, соединение перехватывают, либо сервер переустановили. Ничего не отправляется и не принимается. Заблокируйте приложение и уточните у администратора сервера."],"err.needs_update":["This contact needs to update the app","Контакту нужно обновить приложение"],"err.request_mismatch":["That username does not match this key","Это имя пользователя не соответствует ключу"],"chat.undecryptable":["Some messages could not be decrypted","Некоторые сообщения не удалось расшифровать"],"req.title":["Message request","Запрос на переписку"],"req.note":["Someone you have not added wrote to you. Nothing is trusted yet. Enter the username you expect and it is accepted only if its published key is this one.","Вам написал тот, кого вы не добавляли. Пока ему ничего не доверяется. Введите ожидаемое имя пользователя: оно будет принято, только если его опубликованный ключ совпадает с этим."],"req.fingerprint":["Key fingerprint","Отпечаток ключа"],"req.username":["Username","Имя пользователя"],"req.accept":["Accept","Принять"],"req.block":["Block","Заблокировать"],"key.reset":["Reset pinned key","Сбросить запомненный ключ"],"key.reset_title":["Reset the pinned server key?","Сбросить запомненный ключ сервера?"],"key.reset_warn":["Only do this if you know the server was reinstalled. Otherwise someone may be intercepting your connection.","Делайте это, только если точно знаете, что сервер переустановили. Иначе кто-то может перехватывать ваше соединение."],"key.reset_do":["Yes, reset the key","Да, сбросить ключ"],"key.lock":["Lock","Заблокировать"],"dlg.clear_text":["All messages in this chat are removed from this device.","Все сообщения в этом чате будут удалены на этом устройстве."],"date.today":["Today","Сегодня"],"date.yesterday":["Yesterday","Вчера"],"err.no_channel":["Unknown channel.","Неизвестный канал."],"err.channel_readonly":["Only the owner can post in this channel.","Писать в этот канал может только владелец."],"err.channel_title":["Enter a channel name (up to 64 characters).","Введите название канала (до 64 символов)."],"err.about_long":["The text is too long (up to 140 characters).","Текст слишком длинный (до 140 символов)."],"err.channel_big":["A channel can have at most 200 subscribers.","В канале не больше 200 подписчиков."],"err.media_big":["The file is too large.","Файл слишком большой."],"err.media_type":["This file type is not supported.","Этот тип файла не поддерживается."],"err.media_bad":["The file could not be read.","Не удалось прочитать файл."],"stat.tor_off":["Tor off","Tor выкл."],"stat.onion":["Onion","Onion"],"stat.onion_tip":["Tor is connected and the app reaches the server through its onion address.","Tor подключён, приложение подключается к серверу через onion-адрес."],"stat.e2ee":["E2EE","E2EE"],"stat.e2ee_tip":["Messages are end-to-end encrypted.","Сообщения защищены сквозным шифрованием."],"stat.pin":["PIN","PIN"],"stat.nopin":["No PIN","Без PIN"],"stat.lock_tip":["App lock. Click to open Security and privacy.","Блокировка приложения. Нажмите, чтобы открыть «Безопасность и приватность»."],"guide.open":["Open","Открыть"],"guide.back":["Back","Назад"],"guide.next":["Next","Далее"],"guide.done":["Done","Готово"],"guide.skip":["Skip","Пропустить"],"guide.show":["Show the guide","Показать обучение"],"guide.welcome":["A quick tour","Короткое знакомство"],"guide.welcome_text":["Where things are and how to turn on protection. It takes a minute, and you can skip it.","Где что находится и как включить защиту. Это займёт минуту, можно пропустить."],"guide.settings":["Settings","Настройки"],"guide.settings_text":["The menu button opens contacts, new chats and Settings. Settings start with Security and privacy, then Network and Tor, Appearance, Notifications and Account.","Кнопка меню открывает контакты, новые чаты и настройки. Настройки начинаются с раздела «Безопасность и приватность», дальше «Сеть и Tor», «Оформление», «Уведомления» и «Аккаунт»."],"guide.security":["Turn on protection","Включите защиту"],"guide.security_text":["In Security and privacy set a PIN to lock the app, keep screen capture protection on and hide names in notifications. The lock indicator shows whether a PIN is set.","В разделе «Безопасность и приватность» задайте PIN для блокировки, оставьте защиту от снимков экрана включённой и скройте имена в уведомлениях. Индикатор замка показывает, задан ли PIN."],"guide.tor":["Tor and bridges","Tor и мосты"],"guide.tor_text":["Tor hides your IP address from the server: the app connects to its onion address. Bridges are unlisted Tor relays that help where Tor is blocked. The Tor indicator shows the state; click it for network settings.","Tor скрывает ваш IP-адрес от сервера: приложение подключается к его onion-адресу. Мосты — это неопубликованные узлы Tor, они помогают там, где Tor заблокирован. Индикатор Tor показывает состояние, по нажатию открываются настройки сети."],"guide.contacts":["Adding contacts safely","Безопасное добавление контактов"],"guide.contacts_text":["Type @username in the search field to find a person. Get the username from them directly, then compare the safety number on their profile in person or over another channel.","Введите @ник в поле поиска, чтобы найти человека. Узнайте ник у него напрямую, затем сверьте код безопасности в его профиле лично или по другому каналу."],"guide.appearance":["Make it yours","Настройте под себя"],"guide.appearance_text":["Theme, motion, layout and message style are in Settings, Appearance. This guide can be opened again in Settings, About.","Тема, анимация, расположение и стиль сообщений — в разделе «Оформление». Это обучение можно снова открыть в разделе «О программе»."],"look.title":["Theme","Тема"],"look.theme":["Accent","Акцент"],"look.theme_mono":["Graphite","Графит"],"look.theme_ocean":["Ocean","Океан"],"look.theme_dusk":["Dusk","Сумерки"],"look.theme_aurora":["Aurora","Сияние"],"look.theme_ember":["Ember","Угли"],"look.theme_slate":["Slate","Сланец"],"look.theme_custom":["Custom","Свой"],"look.color":["Color","Цвет"],"look.two_colors":["Use two colors","Два цвета"],"look.custom_note":["Pick two or three colors for your own gradient. It colors buttons, your messages and the header.","Выберите два или три цвета для своего градиента. Он окрашивает кнопки, ваши сообщения и шапку."],"look.pv_name":["Preview","Предпросмотр"],"look.pv_in":["Did the photos arrive?","Фото дошли?"],"look.pv_out":["Yes, all of them. Thanks!","Да, все. Спасибо!"],"look.animated":["Moving gradient background","Движущийся градиентный фон"],"look.animated_note":["A slow, dim gradient behind the chats. Off when motion is off.","Медленный приглушённый градиент за чатами. Выключен, если анимация выключена."],"look.motion_title":["Motion","Анимация"],"look.motion":["Animations","Анимации"],"look.motion_off":["Off","Выкл."],"look.motion_subtle":["Subtle","Мягкие"],"look.motion_full":["Full","Полные"],"look.motion_note":["When reduced motion is on in Windows, animations stay off.","Если в Windows включено уменьшение анимации, анимации остаются выключенными."],"look.depth":["Depth effect","Эффект глубины"],"look.depth_note":["Cards and messages tilt slightly toward the pointer.","Карточки и сообщения слегка наклоняются за указателем."],"look.layout":["Layout","Расположение"],"look.list":["Chat list","Список чатов"],"look.list_left":["Left","Слева"],"look.list_right":["Right","Справа"],"look.list_top":["Top","Сверху"],"look.density":["Density","Плотность"],"look.density_comfortable":["Comfortable","Свободно"],"look.density_compact":["Compact","Компактно"],"look.width_note":["Drag the edge of the chat list to change its width.","Перетащите край списка чатов, чтобы изменить его ширину."],"look.messages":["Messages","Сообщения"],"look.bubble":["Bubbles","Пузыри"],"look.bubble_rounded":["Rounded","Скруглённые"],"look.bubble_sharp":["Sharp","Острые"],"look.bubble_minimal":["Minimal","Минимальные"],"look.radius":["Corner radius","Радиус углов"],"look.font":["Text size","Размер текста"],"look.wallpaper":["Chat background","Фон чата"],"look.wallpaper_none":["Black","Чёрный"],"look.wallpaper_solid":["Solid","Цвет"],"look.wallpaper_gradient":["Gradient","Градиент"],"look.avatar":["Avatars","Аватары"],"look.avatar_circle":["Circle","Круг"],"look.avatar_rounded":["Rounded","Скруглённые"],"look.avatar_square":["Square","Квадрат"],"look.reset":["Reset to default","Сбросить оформление"],"group.members_1":["member","участник"],"group.members_2":["members","участника"],"media.none":["No photos or videos yet.","Фото и видео пока нет."],"d.upd_none":["You have the latest version.","У вас последняя версия."],"d.delete_ok":["Delete","Удалить"],"d.idle":["Lock after idle, minutes","Блокировать после простоя, мин"],"d.socks5":["SOCKS5 proxy, host:port","SOCKS5-прокси, host:port"],"d.flash":["Flash the taskbar on new messages","Мигать на панели задач"],"d.flash_note":["Message text is not shown.","При новых сообщениях; текст не показывается."],"d.delete_here":["Delete from this device","Удалить с этого устройства"],"d.server":["Server","Сервер"],"d.splash_a":["NETWORK INTERCEPTED","СЕТЬ ПЕРЕХВАЧЕНА"],"d.splash_b":["EXCEPT THIS CHANNEL","КРОМЕ ЭТОГО КАНАЛА"],"d.onb1":["Keys stay on your device. The server sees only the queue and the time.","Ключи остаются на устройстве. Сервер видит только очередь и время."],"d.onb2":["Compare the 30-digit safety number.","Сверьте 30-значный номер безопасности."],"d.onb3":["Disappearing messages, Tor by default, cover traffic.","Исчезающие сообщения, Tor по умолчанию, маскирующий трафик."],"d.start":["Start","Начать"],"d.chats":["Chats","Чаты"],"d.sound":["Sound","Звук"],"d.verify":["Verify","Проверка"],"d.about_short":["About","О себе"],"d.pin4":["4 digits","4 цифры"],"d.pin6":["6 digits","6 цифр"],"d.erase":["Erase","Стереть"],"d.show_secret":["Show","Показать"],"d.copied":["Copied.","Скопировано."],"d.compressed":["compressed to {w}×{h} · metadata removed · {kb} KB","сжато до {w}×{h} · метаданные удалены · {kb} КБ"],"d.post1":["Aegis 0.2.5. Tor is now built in and on by default. The app reaches the server through its onion address and sends nothing until Tor is connected. Where Tor is blocked, turn on bridges: Snowflake, obfs4 or your own lines.","Aegis 0.2.5. Tor теперь встроен в приложение и включён по умолчанию. Aegis подключается к серверу через onion-адрес и ничего не отправляет, пока Tor не подключился. Там, где Tor заблокирован, включите мосты: Snowflake, obfs4 или свои строки."],"d.post2":["PIN and duress. Unlock with 4 or 6 digits instead of the password. After five wrong tries the PIN stops working and only the password opens the vault. A duress PIN erases the account from the device and shows the usual wrong-PIN message.","PIN и принуждение. Входите четырьмя или шестью цифрами вместо пароля. После пяти неверных попыток PIN перестаёт действовать, и хранилище открывает только пароль. PIN принуждения стирает аккаунт с устройства и показывает обычное сообщение о неверном PIN."],"d.post3":["Media compression. Photos are re-encoded as JPEG, at most 1600 px on the long side, with EXIF and other metadata removed. Videos lose their metadata too. Files up to 40 MB.","Сжатие медиа. Фото перекодируются в JPEG не больше 1600 px по длинной стороне, EXIF и другие метаданные удаляются. Из видео метаданные тоже вычищаются. Файлы до 40 МБ."],"d.post4":["Cover traffic. While the app is open it talks to the network on its own schedule: when there is no real request, a dummy one of the same size goes out, so the server cannot tell when you are really talking. Off, Normal or Strong in Network and Tor. It stops while Aegis is locked or minimized.","Маскирующий трафик. Пока приложение открыто, оно ходит в сеть по своему расписанию: если настоящего запроса нет, уходит пустой такого же размера, и сервер не видит, когда вы действительно общаетесь. Выключен, Обычный или Усиленный — в разделе «Сеть и Tor». Пока Aegis заблокирован или свёрнут, трафик останавливается."],"d.cover_real":["real","настоящие"],"d.cover_dummy":["dummy","пустые"],"d.gate_create":["Creating your account","Создаём аккаунт"],"d.gate_open":["Signing in","Входим"],"d.gate_done":["Account created","Аккаунт создан"],"d.gate_keys":["Generating keys","Генерация ключей"],"d.gate_pow":["Registration puzzle","Задача регистрации"],"d.zoom_in":["Zoom in","Увеличить"],"d.zoom_out":["Zoom out","Уменьшить"]};
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
    const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true, powerPreference: 'high-performance' });
    renderer.setClearColor(0x000000, 0);
    renderer.toneMapping = THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = 1.05;
    const scene = new THREE.Scene();
    const FOV = 35, CZ = 10, N = 480, RIM = 0.9;
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
      const n = 700;
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
      renderer.setPixelRatio(Math.min(devicePixelRatio || 1, 1.5));
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
    go(ENV.tab === 'unlock' ? 'auth' : 'onb', { tr: 'zoom' });
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
  if (o.keep) { F.create.user.input.value = o.keep.u; F.create.display.input.value = o.keep.d; F.create.display.count(); }
  if (o.errorText && F[cur]) { const k = Object.keys(F[cur])[0]; setTimeout(() => { F[cur][k].error(o.errorText); sync(cur); }, 400); }
  el._enter = () => {
    AegisScene.show('shield', obj, { morph: true });
    if (isDesk()) setTimeout(() => forms[cur].querySelector('input').focus({ preventScroll: true }), reduced ? 0 : 450);
  };
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


// bridge.js
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

const SCREENS = { splash: () => scrSplash(), onb: () => scrOnb(), auth: o => scrAuth(o), gate: o => scrGate(o) };
let curScr = null, scrName = '';
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
      go(booted ? 'auth' : 'splash', { tr: 'fade' });
      booted = true;
    }
    return;
  }
  booted = true;
  if (!entryOn) return;
  const w = ENV.wait;
  ENV.wait = null;
  if (scrName === 'gate' && w && w.ok) w.ok();
  else if (scrName === 'auth') go('gate', { acct: { username: (w && w.user) || '' }, tr: 'push' });
  else ENV.leave();
}

window.aegisEntry = { update: entryUpdate };

})();

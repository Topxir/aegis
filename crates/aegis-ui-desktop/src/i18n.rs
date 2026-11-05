//! All user-visible strings, English and Russian, in one table.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Lang {
    Ru,
    En,
}

impl Lang {
    pub fn code(self) -> &'static str {
        match self {
            Lang::Ru => "ru",
            Lang::En => "en",
        }
    }

    /// Accepts codes like `ru`, `ru-RU`, `en-US`.
    pub fn from_code(s: &str) -> Option<Self> {
        let p = s.trim().get(..2)?.to_ascii_lowercase();
        match p.as_str() {
            "ru" => Some(Lang::Ru),
            "en" => Some(Lang::En),
            _ => None,
        }
    }
}

/// Looks up `key`. A missing key yields a visible marker; a test checks that none is used.
pub fn tr(lang: Lang, key: &str) -> &'static str {
    match TABLE.iter().find(|(k, _, _)| *k == key) {
        Some((_, en, ru)) => match lang {
            Lang::En => en,
            Lang::Ru => ru,
        },
        None => "??",
    }
}

const E2EE_EN: &str = "Messages are end-to-end encrypted. The server sees which queue receives a message and when, not its contents.";
const E2EE_RU: &str = "Сообщения шифруются сквозным шифрованием. Сервер видит, в какую очередь и когда пришло сообщение, но не его содержимое.";

#[rustfmt::skip]
static TABLE: &[(&str, &str, &str)] = &[
    ("auth.tagline", "No phone number, no email, no real name. A username and a password are enough.", "Без номера телефона, почты и настоящего имени. Достаточно ника и пароля."),
    ("auth.eyebrow", "PRIVATE BY DEFAULT", "ПРИВАТНО ПО УМОЛЧАНИЮ"),
    ("auth.chip1", "end-to-end encrypted", "сквозное шифрование"),
    ("auth.chip2", "no phone, no email", "без телефона и почты"),
    ("auth.chip3", "open source", "открытый код"),
    ("auth.foot", "Your boundaries. Your keys.", "Ваши границы. Ваши ключи."),
    ("auth.headline", "Everyone has a right to a private space.", "У каждого есть право на личное пространство."),
    ("auth.pwnote", "The password cannot be recovered. The server never receives it.", "Пароль не восстанавливается. Сервер его никогда не получает."),
    ("chat.hint", "End-to-end encrypted. The server sees only the queue and the time.", "Сквозное шифрование. Сервер видит только очередь и время."),
    ("contact.key_verified", "key verified", "ключ проверен"),
    ("ttl.short", "disappearing", "исчезают"),
    ("status.online", "Connected", "Подключено"),
    ("status.offline", "No connection", "Нет соединения"),
    ("status.connecting", "Connecting", "Подключение"),
    ("auth.tab_unlock", "Unlock", "Войти"),
    ("auth.tab_create", "Create", "Создать"),
    ("auth.tab_import", "Import", "Импорт"),
    ("auth.unlock", "Unlock", "Войти"),
    ("auth.create", "Create account", "Создать аккаунт"),
    ("auth.import", "Import", "Импортировать"),
    ("auth.import_note", "Enter the full path of a vault file exported from Aegis. It is decrypted first and only then copied into the data folder.", "Укажите полный путь к файлу, экспортированному из Aegis. Сначала он расшифровывается и только потом копируется в папку данных."),
    ("f.username", "Username", "Ник"),
    ("f.username_new", "Username (a-z, 0-9, _)", "Ник (a-z, 0-9, _)"),
    ("f.display", "Display name", "Отображаемое имя"),
    ("f.password", "Password", "Пароль"),
    ("f.password_new", "Password (10+ characters)", "Пароль (от 10 символов)"),
    ("f.confirm", "Repeat password", "Повторите пароль"),
    ("f.vault_path", "Vault file path", "Путь к файлу"),
    ("f.contact_username", "Username", "Ник"),
    ("f.group_title", "Group name", "Название группы"),
    ("f.endpoint", "Server address", "Адрес сервера"),
    ("f.socks5", "SOCKS5 proxy (host:port, optional)", "SOCKS5-прокси (host:port, необязательно)"),
    ("f.idle", "Lock after idle minutes (0 = never)", "Блокировать после простоя, минут (0 — никогда)"),
    ("f.export_path", "Full path for the exported file", "Полный путь для файла экспорта"),
    ("f.confirm_name", "Type your username to confirm", "Введите свой ник для подтверждения"),
    ("nav.settings", "Settings", "Настройки"),
    ("nav.lock", "Lock", "Заблокировать"),
    ("nav.new_chat", "New chat", "Новый чат"),
    ("nav.new_group", "New group", "Новая группа"),
    ("list.empty", "No chats yet. Start one with a username.", "Чатов пока нет. Начните с ника собеседника."),
    ("list.filter", "Filter chats", "Фильтр чатов"),
    ("main.welcome_title", "Aegis", "Aegis"),
    ("main.pick", "Select a chat or start a new one.", "Выберите чат или начните новый."),
    ("main.e2ee", E2EE_EN, E2EE_RU),
    ("chat.placeholder", "Message", "Сообщение"),
    ("chat.send", "Send", "Отправить"),
    ("chat.empty", "No messages yet.", "Сообщений пока нет."),
    ("chat.ttl_on", "Disappearing messages are on for messages you send. They are deleted on both devices when the timer ends.", "Исчезающие сообщения включены для ваших исходящих. По истечении таймера они удаляются на обоих устройствах."),
    ("msg.sending", "sending...", "отправка..."),
    ("msg.failed", "not sent", "не отправлено"),
    ("msg.retry", "Retry", "Повторить"),
    ("ttl.label", "Disappearing messages", "Исчезающие сообщения"),
    ("ttl.off", "Off", "Выкл"),
    ("ttl.1h", "1 hour", "1 час"),
    ("ttl.1d", "1 day", "1 день"),
    ("ttl.7d", "7 days", "7 дней"),
    ("warn.key_changed", "The keys of", "Ключи контакта"),
    ("warn.compare", "have changed. Messages signed with the new keys are not shown until you accept them. Compare the safety number with your contact first.", "изменились. Сообщения с новыми ключами не показываются, пока вы их не примете. Сначала сверьте номер безопасности с собеседником."),
    ("warn.group_only", "differ from the pinned ones in a group message. The message was dropped. Keys can only be accepted from a direct message.", "в групповом сообщении отличаются от сохранённых. Сообщение отброшено. Принять новые ключи можно только из личного сообщения."),
    ("warn.view", "Safety number", "Номер безопасности"),
    ("warn.accept", "Accept new key", "Принять новый ключ"),
    ("warn.dismiss", "Dismiss", "Скрыть"),
    ("contact.title", "Contact", "Контакт"),
    ("contact.verified", "verified", "проверен"),
    ("contact.unverified", "not verified", "не проверен"),
    ("contact.safety", "Safety number", "Номер безопасности"),
    ("contact.safety_note", "Compare these numbers with your contact over another channel. If they match, nobody replaced the keys between you.", "Сверьте эти числа с собеседником по другому каналу. Если они совпали, ключи по дороге никто не подменил."),
    ("contact.mark_verified", "Mark as verified", "Отметить как проверенный"),
    ("contact.delete", "Delete chat and contact", "Удалить чат и контакт"),
    ("newchat.note", "Enter the exact username of the person. Users cannot be searched. The server returns the public keys registered under that name, and they are pinned on first use.", "Введите точный ник человека. Поиска пользователей нет. Сервер возвращает публичные ключи, зарегистрированные под этим ником, и они запоминаются при первом использовании."),
    ("newchat.add", "Start chat", "Начать чат"),
    ("newgroup.note", "Up to 100 members including you. Only existing contacts can be added. Every member receives the group key in a direct message.", "До 100 участников включая вас. Добавить можно только существующих контактов. Каждый участник получает ключ группы в личном сообщении."),
    ("newgroup.members", "Members", "Участники"),
    ("newgroup.no_contacts", "Add contacts first.", "Сначала добавьте контакты."),
    ("newgroup.create", "Create group", "Создать группу"),
    ("group.info", "Group", "Группа"),
    ("group.members_n", "members", "участников"),
    ("group.you", "you", "вы"),
    ("group.creator", "creator", "создатель"),
    ("group.resend", "Resend invite", "Отправить приглашение снова"),
    ("group.leave", "Leave group", "Покинуть группу"),
    ("group.leave_note", "Leaving deletes the group from this device only. The other members keep the group key and can still read what they receive.", "Выход удаляет группу только на этом устройстве. У остальных участников ключ группы остаётся, и они продолжают читать свои сообщения."),
    ("dlg.delete_chat", "Delete chat", "Удалить чат"),
    ("dlg.delete_chat_text", "This removes the chat and the pinned keys of", "Будут удалены чат и сохранённые ключи контакта"),
    ("dlg.delete_account_text", "This deletes the vault file on this device. Without an exported copy the account cannot be restored. Type", "Будет удалён файл хранилища на этом устройстве. Без экспортированной копии аккаунт не восстановить. Введите"),
    ("common.back", "Back", "Назад"),
    ("common.cancel", "Cancel", "Отмена"),
    ("common.close", "Close", "Закрыть"),
    ("common.save", "Save", "Сохранить"),
    ("set.profile", "Profile", "Профиль"),
    ("set.connection", "Connection and lock", "Соединение и блокировка"),
    ("set.conn_note", "The default address is behind Cloudflare. TLS ends there, so Cloudflare can see your IP address and when you connect, but not message contents. A SOCKS5 proxy hides your address from the server operator and Cloudflare. Names are resolved through the proxy.", "Адрес по умолчанию стоит за Cloudflare. TLS заканчивается там, поэтому Cloudflare видит ваш IP-адрес и время подключений, но не содержимое сообщений. SOCKS5-прокси скрывает ваш адрес от оператора сервера и Cloudflare. Имена разрешаются через прокси."),
    ("set.flash", "Flash the taskbar on new messages (no message text is shown)", "Мигать на панели задач при новых сообщениях (текст не показывается)"),
    ("set.test", "Test connection", "Проверить соединение"),
    ("set.language", "Language", "Язык"),
    ("set.lang_note", "Takes effect immediately.", "Применяется сразу."),
    ("set.backup", "Backup", "Резервная копия"),
    ("set.backup_note", "Export copies the encrypted vault file to the path you give. It is protected by your password. Existing files are not overwritten.", "Экспорт копирует зашифрованный файл хранилища по указанному пути. Он защищён вашим паролем. Существующие файлы не перезаписываются."),
    ("set.export", "Export vault", "Экспортировать"),
    ("set.danger", "Delete account data", "Удаление данных аккаунта"),
    ("set.delete_note", "Deletes the vault file on this device only. The name stays registered on the server and cannot be reused.", "Удаляет только файл хранилища на этом устройстве. Ник остаётся занят на сервере и не может быть использован снова."),
    ("set.delete", "Delete account data on this device", "Удалить данные аккаунта на этом устройстве"),
    ("set.about", "About", "О программе"),
    ("set.about_text", "Aegis is an experimental end-to-end encrypted messenger. The protocol and the source code are public.", "Aegis — экспериментальный мессенджер со сквозным шифрованием. Протокол и исходный код открыты."),
    ("set.about_font", "Interface fonts: Geist and Geist Mono, SIL Open Font License 1.1.", "Шрифты интерфейса: Geist и Geist Mono, лицензия SIL Open Font License 1.1."),
    ("conn.running", "Testing...", "Проверка..."),
    ("conn.ok", "The server answered.", "Сервер ответил."),
    ("busy.create", "Creating account: generating keys and solving the registration puzzle...", "Создание аккаунта: генерация ключей и решение задачи регистрации..."),
    ("busy.unlock", "Unlocking...", "Вход..."),
    ("busy.lookup", "Looking up the user...", "Поиск пользователя..."),
    ("busy.group", "Creating group and sending invites...", "Создание группы и отправка приглашений..."),
    ("busy.profile", "Saving profile...", "Сохранение профиля..."),
    ("ok.saved", "Saved.", "Сохранено."),
    ("ok.exported", "Exported to", "Экспортировано в"),
    ("ok.deleted", "Account data deleted from this device.", "Данные аккаунта удалены с этого устройства."),
    ("ok.invite_sent", "Invite sent to", "Приглашение отправлено:"),
    ("err.generic", "Something went wrong.", "Что-то пошло не так."),
    ("err.taken", "This username is already taken.", "Этот ник уже занят."),
    ("err.queue_full", "The server refused the request: rate limit or full queue. Try again later.", "Сервер отклонил запрос: лимит или переполненная очередь. Повторите позже."),
    ("err.rejected", "The server rejected the request.", "Сервер отклонил запрос."),
    ("err.network", "Could not reach the server.", "Не удалось связаться с сервером."),
    ("err.password", "Wrong password or damaged vault file.", "Неверный пароль или повреждённый файл."),
    ("err.username", "Invalid username.", "Недопустимый ник."),
    ("err.endpoint", "Invalid server address.", "Недопустимый адрес сервера."),
    ("err.too_long", "The message is too long.", "Сообщение слишком длинное."),
    ("err.confirm", "The passwords do not match.", "Пароли не совпадают."),
    ("err.confirm_name", "The username does not match.", "Ник не совпадает."),
    ("err.password_short", "The password must have at least 10 characters.", "Пароль должен содержать не меньше 10 символов."),
    ("err.display", "Invalid display name (1 to 64 characters).", "Недопустимое имя (от 1 до 64 символов)."),
    ("err.exists", "An account with this name already exists on this device.", "Аккаунт с таким ником уже есть на этом устройстве."),
    ("err.file_exists", "The file already exists. Choose another path.", "Файл уже существует. Выберите другой путь."),
    ("err.path", "Enter a full path in an existing folder.", "Укажите полный путь в существующей папке."),
    ("err.no_account", "No account with this username on this device.", "На этом устройстве нет аккаунта с таким ником."),
    ("err.vault_format", "The file is not a valid Aegis vault.", "Файл не является хранилищем Aegis."),
    ("err.disk", "Could not read or write the file.", "Не удалось прочитать или записать файл."),
    ("err.locked", "Not unlocked.", "Хранилище заблокировано."),
    ("err.self", "That is your own username.", "Это ваш собственный ник."),
    ("err.not_found", "No user with this username on the server.", "Пользователь с таким ником на сервере не найден."),
    ("err.empty", "The message is empty.", "Сообщение пустое."),
    ("err.no_contact", "Unknown contact.", "Неизвестный контакт."),
    ("err.no_group", "Unknown group.", "Неизвестная группа."),
    ("err.group_title", "Enter a group name.", "Введите название группы."),
    ("err.group_members", "Select at least one member.", "Выберите хотя бы одного участника."),
    ("err.group_big", "A group can have at most 100 members including you.", "В группе не больше 100 участников, включая вас."),
    ("err.invite_failed", "The group was created, but these invites were not delivered. Resend them from the group page:", "Группа создана, но приглашения не доставлены. Отправьте их снова на странице группы:"),
    ("err.socks", "The proxy must look like host:port.", "Прокси должен иметь вид host:port."),
    ("tab.all", "All", "Все"),
    ("tab.groups", "Groups", "Группы"),
    ("tab.channels", "Channels", "Каналы"),
    ("drawer.account", "Account", "Аккаунт"),
    ("nav.new_channel", "New channel", "Новый канал"),
    ("nav.contacts", "Contacts", "Контакты"),
    ("list.you", "You:", "Вы:"),
    ("list.lookup", "Search the server for", "Искать на сервере:"),
    ("media.photo", "Photo", "Фото"),
    ("media.video", "Video", "Видео"),
    ("chan.official", "Official channel", "Официальный канал"),
    ("chan.channel", "Channel", "Канал"),
    ("chan.subs_n", "subscribers", "подписчиков"),
    ("chan.official_tag", "official", "официальный"),
    ("chan.manage", "Channel", "Канал"),
    ("chan.invite", "Invite selected", "Пригласить выбранных"),
    ("chan.delete", "Delete channel", "Удалить канал"),
    ("chan.leave", "Leave channel", "Покинуть канал"),
    ("chan.leave_note", "The channel is removed from this device only. Posts you already received stay with the other subscribers.", "Канал будет удалён только на этом устройстве. У остальных подписчиков полученные записи останутся."),
    ("chan.key_changed", "The key of the channel owner differs from the saved one. New posts are not shown.", "Ключ владельца канала отличается от сохранённого. Новые записи не показываются."),
    ("menu.info", "Info", "Информация"),
    ("menu.pin", "Pin", "Закрепить"),
    ("menu.unpin", "Unpin", "Открепить"),
    ("menu.mute", "Mute", "Выключить уведомления"),
    ("menu.unmute", "Unmute", "Включить уведомления"),
    ("menu.clear", "Clear history", "Очистить историю"),
    ("menu.more", "More", "Ещё"),
    ("chat.search", "Search in chat", "Поиск в чате"),
    ("chat.attach", "Attach a photo or video", "Прикрепить фото или видео"),
    ("info.media", "Shared media", "Медиа"),
    ("newchannel.note", "Anyone you invite can read what you post. Subscribers cannot write. Up to 200 subscribers.", "Приглашённые читают ваши записи, но писать не могут. До 200 подписчиков."),
    ("newchannel.create", "Create channel", "Создать канал"),
    ("f.channel_title", "Channel name", "Название канала"),
    ("f.about", "About (up to 140 characters)", "О себе (до 140 символов)"),
    ("f.particles", "Particles", "Частицы"),
    ("contacts.chat", "Chat", "Чат"),
    ("acct.profile", "Profile", "Профиль"),
    ("acct.privacy", "Privacy and security", "Приватность и безопасность"),
    ("acct.notifications", "Notifications", "Уведомления"),
    ("acct.appearance", "Appearance", "Оформление"),
    ("acct.connection", "Connection", "Соединение"),
    ("acct.data", "Data and export", "Данные и экспорт"),
    ("pfx.none", "None", "Нет"),
    ("pfx.dust", "Dust", "Пыль"),
    ("pfx.snow", "Snow", "Снег"),
    ("pfx.embers", "Embers", "Угли"),
    ("pfx.orbit", "Orbit", "Орбита"),
    ("pfx.rain", "Rain", "Дождь"),
    ("profile.note", "Your name, about line and particles are sent to your contacts.", "Имя, строка о себе и частицы отправляются вашим контактам."),
    ("priv.protect", "Hide the window from screen capture", "Скрывать окно от захвата экрана"),
    ("priv.protect_note", "Screenshots and screen sharing show a blank window.", "На снимках и в трансляции экрана окно будет пустым."),
    ("priv.pin", "PIN", "PIN-код"),
    ("priv.set_pin", "Set PIN", "Задать PIN"),
    ("priv.set_duress", "Set duress PIN", "Задать PIN принуждения"),
    ("priv.pin_note", "With a PIN you unlock with 4 or 6 digits instead of the password. The server counts the attempts and gives up the secret after five wrong ones. A duress PIN erases this account from the device and then shows the usual wrong-PIN message.", "С PIN-кодом вы входите четырьмя или шестью цифрами вместо пароля. Сервер считает попытки и после пяти неверных перестаёт выдавать секрет. PIN принуждения стирает этот аккаунт с устройства и показывает обычное сообщение о неверном PIN."),
    ("priv.pin_on", "A PIN is set.", "PIN-код задан."),
    ("priv.duress_on", "A duress PIN is set.", "PIN принуждения задан."),
    ("priv.remove_pin", "Remove PIN", "Убрать PIN"),
    ("priv.clear_duress", "Remove duress PIN", "Убрать PIN принуждения"),
    ("f.pin", "PIN (4 or 6 digits)", "PIN (4 или 6 цифр)"),
    ("f.pin_confirm", "Repeat the PIN", "Повторите PIN"),
    ("f.pin_current", "Current PIN", "Текущий PIN"),
    ("f.duress", "Duress PIN", "PIN принуждения"),
    ("f.secret", "Password or PIN", "Пароль или PIN"),
    ("busy.pin", "Talking to the server...", "Связь с сервером..."),
    ("ok.pin_set", "PIN set.", "PIN задан."),
    ("ok.pin_removed", "PIN removed.", "PIN убран."),
    ("ok.duress_set", "Duress PIN set.", "PIN принуждения задан."),
    ("ok.duress_cleared", "Duress PIN removed.", "PIN принуждения убран."),
    ("err.pin_format", "A PIN is 4 or 6 digits.", "PIN состоит из 4 или 6 цифр."),
    ("err.pin_mismatch", "The PINs do not match.", "PIN-коды не совпадают."),
    ("err.pin_exists", "A PIN is already set.", "PIN уже задан."),
    ("err.pin_none", "No PIN is set.", "PIN не задан."),
    ("err.pin_wrong", "Wrong PIN. Tries left", "Неверный PIN. Осталось попыток"),
    ("err.pin_throttled", "Try again in a moment.", "Попробуйте через минуту."),
    ("err.pin_gone", "This PIN no longer works. Enter your password.", "Этот PIN больше не действует. Введите пароль."),
    ("err.duress_same", "The duress PIN must differ from your PIN.", "PIN принуждения должен отличаться от вашего PIN."),
    ("notify.on", "Flash the taskbar on new messages", "Мигать на панели задач при новых сообщениях"),
    ("notify.name", "Show the sender name instead of New message", "Показывать имя отправителя вместо Нового сообщения"),
    ("notify.note", "Message text is never shown in notifications. Muted chats stay silent.", "Текст сообщений в уведомлениях не показывается. Чаты без звука молчат."),
    ("conn.cover", "Cover traffic", "Маскирующий трафик"),
    ("conn.cover_note", "Cover traffic hides when you are really talking. It stops while the app is locked or minimized.", "Маскирующий трафик скрывает, когда вы действительно общаетесь. Он останавливается, пока приложение заблокировано или свёрнуто."),
    ("conn.cover_off", "Off", "Выключен"),
    ("conn.cover_std", "Standard", "Обычный"),
    ("conn.cover_high", "High", "Усиленный"),
    ("conn.tor", "Connect through Tor (SOCKS 127.0.0.1:9050/9150)", "Подключаться через Tor (SOCKS 127.0.0.1:9050/9150)"),
    ("conn.tor_note", "Tor must be running on this computer. Without it the app sends nothing.", "Tor должен быть запущен на этом компьютере. Без него приложение ничего не отправляет."),
    ("err.tor_down", "Tor is not running: nothing answers on the proxy address.", "Tor не запущен: по адресу прокси никто не отвечает."),
    ("err.server_key_changed", "The server key changed.", "Ключ сервера изменился."),
    ("err.server_key_unset", "The server key is not confirmed yet. Check the connection.", "Ключ сервера ещё не подтверждён. Проверьте подключение."),
    ("chan.official_off", "Official channel (not available yet)", "Официальный канал (пока недоступен)"),
    ("key.title", "Server key changed", "Ключ сервера изменился"),
    ("key.text", "This server now shows a different transport key than the one pinned on first use. Someone may be intercepting the connection, or the server was reinstalled. Nothing is sent or received. Lock the app and ask the server operator before continuing.", "Сервер теперь показывает другой транспортный ключ, чем тот, что был запомнен при первом подключении. Возможно, соединение перехватывают, либо сервер переустановили. Ничего не отправляется и не принимается. Заблокируйте приложение и уточните у администратора сервера."),
    ("err.needs_update", "This contact needs to update the app", "Контакту нужно обновить приложение"),
    ("err.request_mismatch", "That username does not match this key", "Это имя пользователя не соответствует ключу"),
    ("chat.undecryptable", "Some messages could not be decrypted", "Некоторые сообщения не удалось расшифровать"),
    ("req.title", "Message request", "Запрос на переписку"),
    ("req.note", "Someone you have not added wrote to you. Nothing is trusted yet. Enter the username you expect and it is accepted only if its published key is this one.", "Вам написал тот, кого вы не добавляли. Пока ему ничего не доверяется. Введите ожидаемое имя пользователя: оно будет принято, только если его опубликованный ключ совпадает с этим."),
    ("req.fingerprint", "Key fingerprint", "Отпечаток ключа"),
    ("req.username", "Username", "Имя пользователя"),
    ("req.accept", "Accept", "Принять"),
    ("req.block", "Block", "Заблокировать"),
    ("key.reset", "Reset pinned key", "Сбросить запомненный ключ"),
    ("key.reset_title", "Reset the pinned server key?", "Сбросить запомненный ключ сервера?"),
    ("key.reset_warn", "Only do this if you know the server was reinstalled. Otherwise someone may be intercepting your connection.", "Делайте это, только если точно знаете, что сервер переустановили. Иначе кто-то может перехватывать ваше соединение."),
    ("key.reset_do", "Yes, reset the key", "Да, сбросить ключ"),
    ("key.lock", "Lock", "Заблокировать"),
    ("dlg.clear_text", "All messages in this chat are removed from this device.", "Все сообщения в этом чате будут удалены на этом устройстве."),
    ("date.today", "Today", "Сегодня"),
    ("date.yesterday", "Yesterday", "Вчера"),
    ("err.no_channel", "Unknown channel.", "Неизвестный канал."),
    ("err.channel_readonly", "Only the owner can post in this channel.", "Писать в этот канал может только владелец."),
    ("err.channel_title", "Enter a channel name (up to 64 characters).", "Введите название канала (до 64 символов)."),
    ("err.about_long", "The text is too long (up to 140 characters).", "Текст слишком длинный (до 140 символов)."),
    ("err.channel_big", "A channel can have at most 200 subscribers.", "В канале не больше 200 подписчиков."),
    ("err.media_big", "The file is too large.", "Файл слишком большой."),
    ("err.media_type", "This file type is not supported.", "Этот тип файла не поддерживается."),
    ("err.media_bad", "The file could not be read.", "Не удалось прочитать файл."),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_and_nonempty() {
        for (i, (k, en, ru)) in TABLE.iter().enumerate() {
            assert!(!en.is_empty() && !ru.is_empty(), "{k}");
            assert!(
                TABLE[i + 1..].iter().all(|(o, _, _)| o != k),
                "duplicate {k}"
            );
        }
    }

    #[test]
    fn every_key_used_in_sources_exists() {
        let sources = [
            include_str!("session.rs"),
            include_str!("engine.rs"),
            include_str!("engine/extra.rs"),
            include_str!("engine/pin.rs"),
            include_str!("controller.rs"),
            include_str!("render.rs"),
            include_str!("media.rs"),
        ];
        let prefixes = [
            "err.", "ok.", "busy.", "warn.", "chat.", "chan.", "menu.", "list.", "nav.", "dlg.",
            "media.", "key.", "acct.", "pfx.", "notify.", "priv.", "date.", "tab.", "info.", "conn.", "req.",
        ];
        for src in sources {
            let body = src.split("#[cfg(test)]").next().unwrap_or_default();
            for part in body.split('"').skip(1).step_by(2) {
                let key_like = part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_');
                if key_like && prefixes.iter().any(|p| part.starts_with(p)) && part.len() > 4 {
                    assert!(
                        TABLE.iter().any(|(k, _, _)| *k == part),
                        "missing translation key {part}"
                    );
                }
            }
        }
    }

    #[test]
    fn language_codes() {
        assert_eq!(Lang::from_code("ru-RU"), Some(Lang::Ru));
        assert_eq!(Lang::from_code("EN"), Some(Lang::En));
        assert_eq!(Lang::from_code("de"), None);
        assert_eq!(Lang::from_code(""), None);
    }
}

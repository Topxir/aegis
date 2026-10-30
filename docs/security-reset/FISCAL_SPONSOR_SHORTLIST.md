# Phase 0 — shortlist fiscal sponsor

- Статус: **ЧЕРНОВИК на утверждение владельцем**
- Дата: 2026-10-30
- Связанные решения: `Q-23`, `Q-25`, `D-0027`
- Связанные документы: `GRANT_PLAN.md`, `PHASE0_Q23_Q28.md`

Это не юридическая и не финансовая консультация. Условия, fees и
требования к юрлицу меняются; перед обращением их нужно проверить у
спонсора и юриста. Публичные данные ниже — ориентир, а не договор.

## 1. Критерии

1. Опыт с open-source/privacy/security проектами.
2. Готовность работать с международным соло-разработчиком без своей
   юрформы.
3. Понятные fees и отчётность.
4. Возможность получать гранты NLnet/OTF/Prototype Fund.
5. Минимальное вмешательство в технические решения и лицензию.
6. Понятно, какие данные о project lead нужны налоговой/фонду и можно ли
   сохранить публичную псевдонимность.
7. Нет требования передать IP или право менять лицензию.

## 2. Кандидаты

| Кандидат | Юрисдикция | Заявленный fee | Плюсы | Риски / что проверить |
|---|---|---|---|---|
| Center for the Cultivation of Technology (CCT) | Германия, gGmbH | ~10% (по публикациям; проверить) | Прямой фокус Internet Freedom/FOSS; гранты, контракты, payroll, отчётность; проекты не обязаны быть европейскими | Немецкое налоговое/трудовое право; KYC и legal name; актуальные fees и приём новых проектов |
| Software in the Public Interest (SPI) | США, 501(c)(3) | ~5% с gross revenue | Низкий fee; donations tax-deductible в США; accounting/legal; Model C | Требует «substantial and significant» проект; ранний Aegis может не подойти; US-юрисдикция |
| Open Source Collective (OSC) | США, 501(c)(6) | ~10% | Быстрый onboarding; глобальные выплаты; помощь с grant paperwork | Не 501(c)(3): donations не tax-deductible; некоторые фонды не дают гранты 501(c)(6) |
| The Commons Conservancy | Нидерланды, foundation | Прямой fee не заявлен; деньги через партнёров | Гибкая «foundation-as-a-service»; IP/governance; связь с NLnet | Сама не держит деньги; нужен партнёр/NLnet; более тяжёлая процедура для соло-проекта |
| MAGIC Grants | США, 501(c)(3) | По условиям fund | Privacy/security-фокус; опыт fiscal host (Privacy Guides) | Funds заточены под крипто-экосистемы; общий messenger может не подойти |

Не shortlist: Software Freedom Conservancy — публично требует существующее
сообщество и проект старше года; Aegis сейчас этому не соответствует.

## 3. Детали

### CCT

Публично описывает себя как charitable non-profit host для международных
FOSS-проектов: принимает пожертвования и гранты, ведёт accounting,
reimbursements, контракты, payroll и отчётность. Фокус — Internet Freedom,
Free Software и social change; проекты не обязаны быть европейскими.
Публикации указывают fee около 10%; актуальные условия нужно запросить.

Почему первый кандидат: ближе всего к privacy/security-профилю и умеет
работать с грантами и подрядчиками. Главный вопрос — готовность работать
с псевдонимным соло-разработчиком и какие данные потребуются для KYC.

### SPI

SPI — 501(c)(3), fiscal sponsor для FOSS-проектов, публично указывает fee
5% с gross revenue и модель, где проект остаётся самостоятельным. Это
самый дешёвый вариант и хорош для US-фондов, но SPI прямо говорит о
«substantial and significant» проектах; ранний Aegis может не пройти.
Подача — formal application и решение board.

### OSC

OSC — 501(c)(6), fiscal host для open-source проектов по всему миру, fee
около 10%, помогает с grant applications и выплатами. Ограничение: не
501(c)(3), поэтому часть фондов (особенно US-charitable) не сможет дать
грант напрямую. Хороший fallback, если CCT/SPI откажут или нужен быстрый
старт.

### The Commons Conservancy

Не обычный fiscal sponsor: «foundation-as-a-service» и governance/IP
infrastructure; деньги идут через партнёров (NLnet, Commons Caretakers).
Полезно для долгосрочного дома проекта, но для первой грантовой заявки
это более тяжёлый путь. Держать как вариант на Phase 5+/после 1.0.

### MAGIC Grants

501(c)(3) с privacy/security-фокусом и опытом fiscal host (Privacy
Guides). Но его funds публично завязаны на крипто-экосистемы (Monero,
Firo, Privacy Guides); Aegis может не попасть в миссию. Спросить, есть ли
general fund/подходящая программа, но не делать основным кандидатом.

## 4. Рекомендация

1. **CCT** — первый запрос: privacy/FOSS-фокус, гранты, международные
   подрядчики.
2. **SPI** — параллельно уточнить, считают ли Aegis достаточно
   «substantial»; если да, 5% выгоднее.
3. **OSC** — fallback для быстрого приёма средств, если фонд допускает
   501(c)(6).
4. **The Commons Conservancy** — долгосрочный governance/IP-вариант, не
   для первой заявки.
5. **MAGIC Grants** — только если подтвердят подходящую программу.

## 5. Что спросить у каждого

1. Принимаете ли вы новые проекты в 2026–2027?
2. Какие fees и что в них входит?
3. Какие данные о project lead нужны для KYC/налоговой и можно ли
   сохранить публичную псевдонимность?
4. Можете ли выступить получателем гранта NLnet/OTF/Prototype Fund?
5. Кто подписывает договор и несёт liability?
6. Можно ли провести внешний аудит через вас?
7. Что происходит с IP/лицензией и можно ли зафиксировать AGPL-3.0-or-later?
8. Какая отчётность и сроки перечисления?
9. Есть ли ограничения на security/privacy-проекты и на анонимность
   пользователей?
10. Можно ли начать с малого гранта на аудит, без полной разработки?

## 6. Шаблон первого письма

> Subject: Fiscal sponsorship inquiry — Aegis, open-source private messenger
>
> Hello,
>
> I am the maintainer of Aegis, an open-source (AGPL-3.0-or-later)
> privacy-focused messenger. We are preparing a grant application for an
> independent security audit and need a fiscal sponsor for the first
> application.
>
> Could you tell me whether you are accepting new projects, your current
> fees, and what legal/tax information you require from an international
> solo maintainer? I can share the threat model, protocol spec and budget
> under NDA.
>
> Thank you.

Не отправлять письмо без решения владельца о раскрытии legal identity
спонсору (публично она может остаться псевдонимной).

## 7. Что нужно от владельца

1. Разрешение обратиться к CCT и SPI (и, при необходимости, к OSC).
2. Решение: допустимо ли раскрыть legal identity/tax info fiscal sponsor
   под NDA; публичная псевдонимность сохраняется.
3. Бюджет на fees/юрконсультацию (вилка в `GRANT_PLAN.md`).
4. Решение по публичности репозитория до internal red team.

## 8. Источники (проверено 2026-10-30)

- CCT: <https://techcultivation.org/>, <https://renewablefreedom.org/projects/center-for-the-cultivation-of-technology/>
- SPI: <https://www.spi-inc.org/>, <https://www.spi-inc.org/projects/associated-project-howto/>
- OSC: <https://docs.oscollective.org/interested-in-joining-osc/acceptance-criteria>, <https://docs.oscollective.org/for-hosted-member-projects/applying-for-and-accepting-grants>
- The Commons Conservancy: <https://www.commonsconservancy.org/>, <https://commonsconservancy.org/how/>
- MAGIC Grants: <https://www.magicgrants.org/>, <https://magicgrants.org/funds/>
- SFC (почему не shortlist): <https://sfconservancy.org/projects/apply/>

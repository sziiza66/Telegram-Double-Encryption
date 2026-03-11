# 1. <span style="color:rgb(250, 250, 250)">Изменения тестового билда</span>

# 1.1 <span style="color:rgb(250, 250, 250)">Точки внедрения шифрования</span>

Во-первых, точки перехвата сообщений были перенесены в упомянутые в прошлом отчёте места (для исходящих сообщений было выбрано место поглубже, чем sender.h):

Входящие сообщения:
``` C++
// session.cpp
void Session::tryToReceive() {
	if (_killed) {
		DEBUG_LOG(("Session Error: can't receive in a killed session"));
		return;
	}
	if (paused()) {
		_needToReceive = true;
		return;
	}
	while (true) {
		auto lock = QWriteLocker(_data->haveReceivedMutex());
		const auto messages = base::take(_data->haveReceivedMessages());
		lock.unlock();
		if (messages.empty()) {
			break;
		}
		const auto guard = QPointer<Session>(this);
		const auto instance = QPointer<Instance>(_instance);
		const auto main = (_shiftedDcId == BareDcId(_shiftedDcId));
		for (const auto &message : messages) {
			if (message.requestId) {
				instance->processCallback(DoubleEncryption::ResponseDecryptor().DecryptResponse(message));
			} else if (main) {
				// Process updates only in main session.
				instance->processUpdate(DoubleEncryption::ResponseDecryptor().DecryptResponse(message));
			}
			if (!instance) {
				return;
			}
		}
		if (!guard) {
			break;
		}
	}
}
```
Вообще, есть ещё более технический уровень, где происходит всякое служебное взаимодействие, получение ack'ов, распаковка через gzip и прочее, но вряд ли эти что-то из этого уровня будет важно в проекте. Разве что наличие сжатия от telegram убивает смысл добавлять своё.


Входящие сообщения, они всегда проходят через сериализацию, поэтому это место ловит их всех:

``` C++
// mtproto_serialized_request.h
template <typename Request, typename>
SerializedRequest SerializedRequest::Serialize(const Request &request) {
	auto encrypted_request = DoubleEncryption::RequestEncryptor().EncryptRequest(request);
	const auto requestSize = tl::count_length(encrypted_request) >> 2;
	auto serialized = Prepare(requestSize);
	encrypted_request.template write<mtpBuffer>(*serialized);
	return serialized;
}
```

# 1.2 <span style="color:rgb(250, 250, 250)">Изменения тестового кода</span>

Большая часть работы состоит в том, что я написал функции/методы для шифрования/расшифрования сообщений, при которой так же нужно их десериализовать, а потом обратно сериализовать.

Я выделил два класса: ResponseDecryptor (дешифратор) и RequestEncryptor (шифратор) с соответствующими методами. Хотя много функций сейчас всё равно лежат в анонимно неймспейсе, сделать их методами не будет проблемой. Т.к. я пока что не работаю с остальными компонентами (БД ключей и т.д.), я пока не тороплюсь с решениями дизайна, которые тоже хочется отдельно обсудить.

Код для дешифратора получился длинным, т.к. нужно много типов сообщений рекурсивное десериализовать. Главным образом стоит выделить шаблонный метод Decrypt, у которого по факту рабочие только специализации, поэтому, возможно, использование шаблона тут неоправдано, но я обяъяснил в комментариях в начале response_decryptor.cpp, почему я так сделал. Опять же, дизайн кода будет изменить несложно, потому что это не изменит логику функций.

# 1.3 <span style="color:rgb(250, 250, 250)">Препятствия в работе со scheme.h</span>

Во время реализации RequestEncryptor, я понял, что классы все классы реквестов, к сожалению, не предоставляют методов для просмотра их приватных полей. Самым простым способом это обойти я решил, что будет редактирование generate.py -- скрипта, генерирующего схему из файла. Я сделал шифратор дружественным классом для всех исходящих сообщений:

``` py
funcsText += '\tfriend class DoubleEncryption::RequestEncryptor;\n'
```

В итоге в схеме теперь:
``` C++
// forward declaration в начале
namespace DoubleEncryption {
class RequestEncryptor;
}
...
class MTPmessages_sendMessage { // RPC method 'messages.sendMessage'
	friend class DoubleEncryption::RequestEncryptor; // Это у каждого RPC к серверу
public:
    ...
}
```

# 2. <span style="color:rgb(250, 250, 250)">Тестирование клиента</span>

# 2.1 <span style="color:rgb(250, 250, 250)">Проверка шифратора и дешифратора</span>

Все сообщения, для которых я написал обработку в коде (по сути только сообщения в чатах и черновики), успешно её проходят: входящие сообщения убирают пометку шифровки и добавляют пометку расшифровки, исходящие добавляют пометку шифровки. Форматирование текста полностью убирается из сообщений перед отправкой, чтобы не передавать лишней информации.

# 2.2 <span style="color:rgb(250, 250, 250)">Необходимость текстовой кодировки</span>

Я проверил, что сервер сделает с сообщением с произвольными байтами, оптравив в сообщении весь диапазон char:

``` C++
const char BytesSuffix[] = {-0x80, -0x7f, -0x7e, -0x7d, -0x7c, -0x7b, -0x7a, -0x79, -0x78, -0x77, -0x76, -0x75, ..., 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f};

```

В итоге получил "���...���" -- последовательность из символов uft8 с байткодом 0xEFBFBD, этот символ используется для замены некорректного utf8 символа.

Значит Base64 или подобная кодировка будет необходима.

# 3. <span style="color:rgb(250, 250, 250)">Прочее исследование</span>

# 3.1 <span style="color:rgb(250, 250, 250)">Критика tdesktop на habr</span>

Я почитал на хабре статью [Критика протокола и оргподходов Telegram. Часть 1, техническая: опыт написания клиента с нуля — TL, MT](https://habr.com/ru/articles/472970/). В ней на момент 2018-2019 годов критикуется протокол mtproto и язык tl (в основном он), а так же документации к ним. В общем, язык tl (на тот момнет) очень сумбурно реализован + много чего заявленного про него вообще не реализовано, из-за чего работать с ним тяжело, много костылей. Так же был такой момент, что после запросов по новой схеме, а потом при отправке сообщений с новой схемой, в ответ начала приходить смесь из ответов разной версии схемы. Там ещё много чего было, но вряд ли это напрямую нужно будет учитывать это где-то в этом проекте.
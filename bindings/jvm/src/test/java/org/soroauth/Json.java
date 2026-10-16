package org.soroauth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON parser for the golden vectors: objects, arrays, strings
 * with escapes, integers, and null. The vectors are machine-written with a
 * fixed shape, and depending on a JSON library for tests would trade a
 * hundred lines here for a network fetch in every clean-room build.
 */
final class Json {
  private final String text;
  private int pos;

  private Json(String text) {
    this.text = text;
  }

  static Object parse(String text) {
    Json json = new Json(text);
    Object value = json.value();
    json.spaces();
    if (json.pos != text.length()) {
      throw new IllegalArgumentException("trailing input at " + json.pos);
    }
    return value;
  }

  @SuppressWarnings("unchecked")
  static Map<String, Object> object(Object value) {
    return (Map<String, Object>) value;
  }

  @SuppressWarnings("unchecked")
  static List<Object> array(Object value) {
    return (List<Object>) value;
  }

  static String string(Object value) {
    return (String) value;
  }

  static long integer(Object value) {
    return ((Number) value).longValue();
  }

  private void spaces() {
    while (pos < text.length() && Character.isWhitespace(text.charAt(pos))) {
      pos++;
    }
  }

  private Object value() {
    spaces();
    if (pos >= text.length()) {
      throw new IllegalArgumentException("truncated input");
    }
    char c = text.charAt(pos);
    switch (c) {
      case '{':
        return object();
      case '[':
        return array();
      case '"':
        return string();
      case 'n':
        expect("null");
        return null;
      case 't':
        expect("true");
        return Boolean.TRUE;
      case 'f':
        expect("false");
        return Boolean.FALSE;
      default:
        return number();
    }
  }

  private void expect(String word) {
    if (!text.startsWith(word, pos)) {
      throw new IllegalArgumentException("want " + word + " at " + pos);
    }
    pos += word.length();
  }

  private Map<String, Object> object() {
    Map<String, Object> out = new LinkedHashMap<>();
    pos++; // {
    spaces();
    if (pos < text.length() && text.charAt(pos) == '}') {
      pos++;
      return out;
    }
    while (true) {
      spaces();
      String key = string();
      spaces();
      if (pos >= text.length() || text.charAt(pos) != ':') {
        throw new IllegalArgumentException("want : at " + pos);
      }
      pos++;
      out.put(key, value());
      spaces();
      if (pos >= text.length()) {
        throw new IllegalArgumentException("truncated object");
      }
      char c = text.charAt(pos++);
      if (c == '}') {
        return out;
      }
      if (c != ',') {
        throw new IllegalArgumentException("want , at " + (pos - 1));
      }
    }
  }

  private List<Object> array() {
    List<Object> out = new ArrayList<>();
    pos++; // [
    spaces();
    if (pos < text.length() && text.charAt(pos) == ']') {
      pos++;
      return out;
    }
    while (true) {
      out.add(value());
      spaces();
      if (pos >= text.length()) {
        throw new IllegalArgumentException("truncated array");
      }
      char c = text.charAt(pos++);
      if (c == ']') {
        return out;
      }
      if (c != ',') {
        throw new IllegalArgumentException("want , at " + (pos - 1));
      }
    }
  }

  private String string() {
    if (text.charAt(pos) != '"') {
      throw new IllegalArgumentException("want string at " + pos);
    }
    pos++;
    StringBuilder out = new StringBuilder();
    while (true) {
      if (pos >= text.length()) {
        throw new IllegalArgumentException("truncated string");
      }
      char c = text.charAt(pos++);
      if (c == '"') {
        return out.toString();
      }
      if (c == '\\') {
        char e = text.charAt(pos++);
        switch (e) {
          case '"':
            out.append('"');
            break;
          case '\\':
            out.append('\\');
            break;
          case '/':
            out.append('/');
            break;
          case 'b':
            out.append('\b');
            break;
          case 'f':
            out.append('\f');
            break;
          case 'n':
            out.append('\n');
            break;
          case 'r':
            out.append('\r');
            break;
          case 't':
            out.append('\t');
            break;
          case 'u':
            out.append((char) Integer.parseInt(text.substring(pos, pos + 4), 16));
            pos += 4;
            break;
          default:
            throw new IllegalArgumentException("bad escape at " + (pos - 1));
        }
      } else {
        out.append(c);
      }
    }
  }

  private Number number() {
    int start = pos;
    if (pos < text.length() && text.charAt(pos) == '-') {
      pos++;
    }
    while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
      pos++;
    }
    return Long.parseLong(text.substring(start, pos));
  }
}

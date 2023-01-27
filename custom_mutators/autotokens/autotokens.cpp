extern "C" {

#include "afl-fuzz.h"

}

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <iostream>
#include <fstream>
#include <unordered_map>
#include <vector>
#include <regex>

#define AUTOTOKENS_DEBUG 0
#define AUTOTOKENS_ONLY_FAV 0
#define AUTOTOKENS_ALTERNATIVE_TOKENIZE 0
#define AUTOTOKENS_CHANGE_MIN 8
#define AUTOTOKENS_WHITESPACE " "
#define AUTOTOKENS_SIZE_MIN 8
#define AUTOTOKENS_SPLICE_MIN 4
#define AUTOTOKENS_SPLICE_MAX 64
#ifndef AUTOTOKENS_SPLICE_DISABLE
  #define AUTOTOKENS_SPLICE_DISABLE 0
#endif

#if AUTOTOKENS_SPLICE_MIN >= AUTOTOKENS_SIZE_MIN
  #error SPLICE_MIN must be lower than SIZE_MIN
#endif

using namespace std;

typedef struct my_mutator {

  afl_state *afl;

} my_mutator_t;

#undef DEBUGF
#define DEBUGF \
  if (unlikely(debug)) fprintf
#define IFDEBUG if (unlikely(debug))

static afl_state *afl_ptr;
static int        debug = AUTOTOKENS_DEBUG;
static int        only_fav = AUTOTOKENS_ONLY_FAV;
static int        alternative_tokenize = AUTOTOKENS_ALTERNATIVE_TOKENIZE;
static u32        current_id;
static u32        valid_structures;
static u32        whitespace_ids;
static u32        extras_cnt, a_extras_cnt;
static u64        all_spaces, all_tabs, all_lf, all_ws;
static u64        all_structure_items;
static u64        fuzz_count;
static unordered_map<string, vector<u32> *> file_mapping;
static unordered_map<u32, vector<u32> *>    id_mapping;
static unordered_map<string, u32>           token_to_id;
static unordered_map<u32, string>           id_to_token;
static string                               whitespace = AUTOTOKENS_WHITESPACE;
static string                               output;
static regex                               *regex_comment_custom;
// multiline requires g++-11 libs :(
static regex regex_comment_star(
    "/\\*([:print:]|\n)*?\\*/",
    regex_constants::optimize /* | regex_constants::multiline */);
static regex        regex_word("[A-Za-z0-9_$.-]+", regex::optimize);
static regex        regex_whitespace(R"([ \t]+)", regex::optimize);
static vector<u32> *s;  // the structure of the currently selected input

u32 good_whitespace_or_singleval() {

  u32 i = rand_below(afl_ptr, current_id);
  if (id_to_token[i].size() == 1) { return i; }
  i = rand_below(afl_ptr, all_ws);
  if (i < all_spaces) {

    return 0;

  } else if (i < all_tabs) {

    return 1;

  } else

    return 2;  // linefeed

}

extern "C" size_t afl_custom_fuzz(my_mutator_t *data, u8 *buf, size_t buf_size,
                                  u8 **out_buf, u8 *add_buf,
                                  size_t add_buf_size, size_t max_size) {

  (void)(data);

  if (s == NULL) {

    *out_buf = NULL;
    return 0;

  }

  vector<u32> m = *s;  // copy of the structure we will modify
  u32         i, m_size = (u32)m.size();

  u32 rounds =
      MAX(AUTOTOKENS_CHANGE_MIN,
          MIN(m_size >> 3, HAVOC_CYCLES * afl_ptr->queue_cur->perf_score *
                               afl_ptr->havoc_div / 256));
  // DEBUGF(stderr, "structure size: %lu, rounds: %u \n", m.size(), rounds);

#if AUTOTOKENS_SPLICE_DISABLE == 1
  #define AUTOTOKENS_MUT_MAX 18
#else
  #define AUTOTOKENS_MUT_MAX 27
#endif

  u32 max_rand = AUTOTOKENS_MUT_MAX, new_item, pos;

  for (i = 0; i < rounds; ++i) {

    switch (rand_below(afl_ptr, max_rand)) {

      /* CHANGE/MUTATE single item */
      case 0 ... 9: {

        pos = rand_below(afl_ptr, m_size);
        u32 cur_item = m[pos];
        do {

          new_item = rand_below(afl_ptr, current_id);

        } while (unlikely(

            new_item == cur_item ||
            (!alternative_tokenize &&
             ((whitespace_ids < new_item && whitespace_ids >= cur_item) ||
              (whitespace_ids >= new_item && whitespace_ids < cur_item)))));

        DEBUGF(stderr, "MUT: %u -> %u\n", cur_item, new_item);
        m[pos] = new_item;
        break;

      }

      /* INSERT (m_size +1 so we insert also after last place) */
      case 10 ... 13: {

        do {

          new_item = rand_below(afl_ptr, current_id);

        } while (unlikely(!alternative_tokenize && new_item >= whitespace_ids));

        u32 pos = rand_below(afl_ptr, m_size + 1);
        m.insert(m.begin() + pos, new_item);
        ++m_size;
        DEBUGF(stderr, "INS: %u at %u\n", new_item, pos);

        if (likely(!alternative_tokenize)) {

          // if we insert an identifier or string we might need whitespace
          if (id_to_token[new_item].size() > 1) {

            // need to insert before?

            if (pos && m[pos - 1] >= whitespace_ids &&
                id_to_token[m[pos - 1]].size() > 1) {

              m.insert(m.begin() + pos, good_whitespace_or_singleval());
              ++m_size;

            }

            if (pos + 1 < m_size && m[pos + 1] >= whitespace_ids &&
                id_to_token[m[pos + 1]].size() > 1) {

              // need to insert after?

              m.insert(m.begin() + pos + 1, good_whitespace_or_singleval());
              ++m_size;

            }

          }

        }

        break;

      }

#if AUTOTOKENS_SPLICE_DISABLE != 1
      /* SPLICING */
      case 14 ... 22: {

        u32  strategy = rand_below(afl_ptr, 4), dst_off, n;
        auto src = id_mapping[rand_below(afl_ptr, valid_structures)];
        u32  src_size = src->size();
        u32  src_off = rand_below(afl_ptr, src_size - AUTOTOKENS_SPLICE_MIN);
        u32  rand_r = 1 + MAX(AUTOTOKENS_SPLICE_MIN,
                              MIN(AUTOTOKENS_SPLICE_MAX, src_size - src_off));

        switch (strategy) {

          // insert
          case 0: {

            dst_off = rand_below(afl_ptr, m_size);
            n = AUTOTOKENS_SPLICE_MIN +
                rand_below(afl_ptr, MIN(AUTOTOKENS_SPLICE_MAX,
                                        rand_r - AUTOTOKENS_SPLICE_MIN));
            m.insert(m.begin() + dst_off, src->begin() + src_off,
                     src->begin() + src_off + n);
            m_size += n;
            DEBUGF(stderr, "SPLICE-INS: %u at %u\n", n, dst_off);

            break;

          }

          // overwrite
          default: {

            dst_off = rand_below(afl_ptr, m_size - AUTOTOKENS_SPLICE_MIN);
            n = AUTOTOKENS_SPLICE_MIN +
                rand_below(
                    afl_ptr,
                    MIN(AUTOTOKENS_SPLICE_MAX - AUTOTOKENS_SPLICE_MIN,
                        MIN(m_size - dst_off - AUTOTOKENS_SPLICE_MIN,
                            src_size - src_off - AUTOTOKENS_SPLICE_MIN)));

            copy(src->begin() + src_off, src->begin() + src_off + n,
                 m.begin() + dst_off);

            DEBUGF(stderr, "SPLICE-MUT: %u at %u\n", n, dst_off);
            break;

          }

        }

        if (likely(!alternative_tokenize)) {

          // do we need a whitespace/token at the beginning?
          if (dst_off && id_to_token[m[dst_off - 1]].size() > 1 &&
              id_to_token[m[dst_off]].size() > 1) {

            m.insert(m.begin() + dst_off, good_whitespace_or_singleval());
            ++m_size;

          }

          // do we need a whitespace/token at the end?
          if (dst_off + n < m_size &&
              id_to_token[m[dst_off + n - 1]].size() > 1 &&
              id_to_token[m[dst_off + n]].size() > 1) {

            m.insert(m.begin() + dst_off + n, good_whitespace_or_singleval());
            ++m_size;

          }

        }

        break;

      }

#endif

      /* ERASE - only if large enough */
      default: {

        if (m_size > 8) {

          do {

            pos = rand_below(afl_ptr, m_size);

          } while (unlikely(m[pos] < whitespace_ids));

          // if what we delete will result in a missing whitespace/token,
          // instead of deleting we switch the item to a whitespace or token.
          if (likely(!alternative_tokenize) && pos && pos + 1 < m_size &&
              id_to_token[m[pos - 1]].size() > 1 &&
              id_to_token[m[pos + 1]].size() > 1) {

            m[pos] = good_whitespace_or_singleval();

          } else {

            m.erase(m.begin() + pos);
            --m_size;

          }

        } else {

          // if the data is already too small do not try to make it smaller
          // again this run.

          max_rand -= 4;

        }

        break;

      }

    }

  }

  u32 m_size_1 = m_size - 1;
  output = "";

  for (i = 0; i < m_size; ++i) {

    output += id_to_token[m[i]];
    if (unlikely(alternative_tokenize && i < m_size_1)) {

      output += whitespace;

    }

  }

  u32 mutated_size = (u32)output.size();
  u8 *mutated_out = (u8 *)output.data();

  if (unlikely(mutated_size > max_size)) { mutated_size = max_size; }

  IFDEBUG {

    DEBUGF(stderr, "MUTATED to %u bytes:\n", mutated_size);
    fwrite(output.data(), 1, mutated_size, stderr);
    DEBUGF(stderr, "\n---\n");

  }

  *out_buf = mutated_out;
  ++fuzz_count;
  return mutated_size;

}

/* I get f*cking stack overflow using C++ regex with a regex of
   "\"[[:print:]]*?\"" if this matches a long string even with regex::optimize
   enabled :-( */
u8 my_search_string(string::const_iterator cur, string::const_iterator ende,
                    string::const_iterator *match_begin,
                    string::const_iterator *match_end) {

  string::const_iterator start = cur, found_begin;
  u8                     quote_type = 0;

  while (cur < ende) {

    switch (*cur) {

      case '"': {

        if (cur == start || *(cur - 1) != '\\') {

          if (!quote_type) {

            found_begin = cur;
            quote_type = 1;

          } else if (quote_type == 1) {

            *match_begin = found_begin;
            *match_end = cur + 1;
            return 1;

          }

        }

        break;

      }

      case '\'': {

        if (cur == start || *(cur - 1) != '\\') {

          if (!quote_type) {

            found_begin = cur;
            quote_type = 2;

          } else if (quote_type == 2) {

            *match_begin = found_begin;
            *match_end = cur + 1;
            return 1;

          }

        }

        break;

      }

      case '\n':
      case '\r':
      case 0: {

        quote_type = 0;
        break;

      }

      default:
        if (unlikely(quote_type && !isprint(*cur))) { quote_type = 0; }
        break;

    }

    ++cur;

  }

  return 0;

}

/* We are not using afl_custom_queue_new_entry() because not every corpus entry
   will be necessarily fuzzed. so we use afl_custom_queue_get() instead */

extern "C" unsigned char afl_custom_queue_get(void                *data,
                                              const unsigned char *filename) {

  (void)(data);

  if (likely(!debug)) {

    if (unlikely(!afl_ptr->custom_only) &&
        ((afl_ptr->shm.cmplog_mode && !afl_ptr->queue_cur->is_ascii) ||
         (only_fav && !afl_ptr->queue_cur->favored))) {

      s = NULL;
      DEBUGF(stderr, "cmplog not ascii or only_fav and not favorite\n");
      return 0;

    }

  }

  // check if there are new dictionary entries and add them to the tokens
  if (valid_structures) {

    while (extras_cnt < afl_ptr->extras_cnt) {

      u32 ok = 1, l = afl_ptr->extras[extras_cnt].len;
      u8 *ptr = afl_ptr->extras[extras_cnt].data;

      for (u32 i = 0; i < l; ++i) {

        if (!isascii((int)ptr[i]) && !isprint((int)ptr[i])) {

          ok = 0;
          break;

        }

      }

      if (ok) {

        token_to_id[(char *)ptr] = current_id;
        id_to_token[current_id] = (char *)ptr;
        ++current_id;

      }

      ++extras_cnt;
      DEBUGF(stderr, "Added from dictionary: \"%s\"\n", ptr);

    }

    while (a_extras_cnt < afl_ptr->a_extras_cnt) {

      u32 ok = 1, l = afl_ptr->a_extras[a_extras_cnt].len;
      u8 *ptr = afl_ptr->a_extras[a_extras_cnt].data;

      for (u32 i = 0; i < l; ++i) {

        if (!isascii((int)ptr[i]) && !isprint((int)ptr[i])) {

          ok = 0;
          break;

        }

      }

      if (ok) {

        token_to_id[(char *)ptr] = current_id;
        id_to_token[current_id] = (char *)ptr;
        ++current_id;

      }

      ++a_extras_cnt;
      DEBUGF(stderr, "Added from auto dictionary: \"%s\"\n", ptr);

    }

  }

  vector<u32> *structure = NULL;
  string       fn = (char *)filename;
  auto         entry = file_mapping.find(fn);

  if (entry == file_mapping.end()) {

    // this input file was not analyzed for tokens yet, so let's do it!

    FILE *fp = fopen((char *)filename, "rb");
    if (!fp) {

      s = NULL;
      return 0;

    }  // should not happen

    fseek(fp, 0, SEEK_END);
    size_t len = (size_t)ftell(fp);

    if (len < AFL_TXT_MIN_LEN) {

      fclose(fp);
      file_mapping[fn] = structure;  // NULL ptr so we don't read the file again
      s = NULL;
      DEBUGF(stderr, "Too short (%lu) %s\n", len, filename);
      return 0;

    }

    string input;
    input.resize(len);
    rewind(fp);

    if (fread((void *)input.data(), 1, len, fp) != len) {

      s = NULL;
      DEBUGF(stderr, "Too short read %s\n", filename);
      return 0;

    }

    fclose(fp);

    if (!afl_ptr->shm.cmplog_mode) {

      // not running with CMPLOG? bad choice, but whatever ...
      // we only want text inputs, so we have to check it ourselves.

      u32 valid_chars = 0;
      for (u32 i = 0; i < len; ++i) {

        if (isascii((int)input[i]) || isprint((int)input[i])) { ++valid_chars; }

      }

      // we want at least 95% of text characters ...
      if (((len * AFL_TXT_MIN_PERCENT) / 100) > valid_chars) {

        file_mapping[fn] = NULL;
        s = NULL;
        DEBUGF(stderr, "Not text (%lu) %s\n", len, filename);
        return 0;

      }

    }

    // DEBUGF(stderr, "Read %lu bytes for %s\nBefore comment trim:\n%s\n",
    // input.size(), filename, input.c_str());

    if (regex_comment_custom) {

      input = regex_replace(input, *regex_comment_custom, "$2");

    } else {

      input = regex_replace(input, regex_comment_star, "");

    }

    DEBUGF(stderr, "After replace %lu bytes for %s\n%s\n", input.size(),
           filename, input.c_str());

    u32  spaces = count(input.begin(), input.end(), ' ');
    u32  tabs = count(input.begin(), input.end(), '\t');
    u32  linefeeds = count(input.begin(), input.end(), '\n');
    bool ends_with_linefeed = input[input.length() - 1] == '\n';
    DEBUGF(stderr, "spaces=%u tabs=%u linefeeds=%u ends=%u\n", spaces, tabs,
           linefeeds, ends_with_linefeed);
    all_spaces += spaces;
    all_tabs += tabs;
    all_lf += linefeeds;
    all_ws = all_spaces + all_tabs + all_lf;

    // now extract all tokens
    vector<string>         tokens;
    string::const_iterator cur = input.begin(), ende = input.end(), found, prev,
                           match_begin, match_end;

    DEBUGF(stderr, "START!\n");

    if (likely(!alternative_tokenize)) {

      while (my_search_string(cur, ende, &match_begin, &match_end)) {

        prev = cur;
        found = match_begin;
        cur = match_end;

        IFDEBUG {

          string foo(match_begin, match_end);
          DEBUGF(stderr,
                 "string %s found at start %lu offset %lu continue at %lu\n",
                 foo.c_str(), prev - input.begin(), found - prev,
                 cur - input.begin());

        }

        if (prev < found) {  // there are items between search start and find
          while (prev < found) {

            if (isspace(*prev)) {

              auto start = prev;
              while (isspace(*prev)) {

                ++prev;

              }

              tokens.push_back(std::string(start, prev));
              DEBUGF(stderr, "WHITESPACE %ld \"%s\"\n", prev - start,
                     tokens[tokens.size() - 1].c_str());

            } else if (isalnum(*prev) || *prev == '$' || *prev == '_') {

              auto start = prev;
              while (isalnum(*prev) || *prev == '$' || *prev == '_' ||
                     *prev == '.' || *prev == '/') {

                ++prev;

              }

              tokens.push_back(string(start, prev));
              DEBUGF(stderr, "IDENTIFIER %ld \"%s\"\n", prev - start,
                     tokens[tokens.size() - 1].c_str());

            } else {

              tokens.push_back(string(prev, prev + 1));
              DEBUGF(stderr, "OTHER \"%c\"\n", *prev);
              ++prev;

            }

          }

        }

        tokens.push_back(string(match_begin, match_end));
        DEBUGF(stderr, "TOK: %s\n", tokens[tokens.size() - 1].c_str());

      }

      DEBUGF(stderr, "AFTER all strings\n");

      if (cur < ende) {

        while (cur < ende) {

          if (isspace(*cur)) {

            auto start = cur;
            while (isspace(*cur)) {

              ++cur;

            }

            tokens.push_back(std::string(start, cur));
            DEBUGF(stderr, "WHITESPACE %ld \"%s\"\n", cur - start,
                   tokens[tokens.size() - 1].c_str());

          } else if (isalnum(*cur) || *cur == '$' || *cur == '_') {

            auto start = cur;
            while (isalnum(*cur) || *cur == '$' || *cur == '_' || *cur == '.' ||
                   *cur == '/') {

              ++cur;

            }

            tokens.push_back(std::string(start, cur));
            DEBUGF(stderr, "IDENTIFIER %ld \"%s\"\n", cur - start,
                   tokens[tokens.size() - 1].c_str());

          } else {

            tokens.push_back(std::string(cur, cur + 1));
            DEBUGF(stderr, "OTHER \"%c\"\n", *cur);
            ++cur;

          }

        }

      }

    } else {

      // alternative tokenize
      while (my_search_string(cur, ende, &match_begin, &match_end)) {

        prev = cur;
        found = match_begin;
        cur = match_end;
        IFDEBUG {

          string foo(match_begin, match_end);
          DEBUGF(stderr,
                 "string %s found at start %lu offset %lu continue at %lu\n",
                 foo.c_str(), prev - input.begin(), found - prev,
                 cur - input.begin());

        }

        if (prev < found) {  // there are items between search start and find

          sregex_token_iterator it{prev, found, regex_whitespace, -1};
          vector<std::string>   tokenized{it, {}};
          tokenized.erase(std::remove_if(tokenized.begin(), tokenized.end(),
                                         [](std::string const &s) {

                                           return s.size() == 0;

                                         }),

                          tokenized.end());
          tokens.reserve(tokens.size() + tokenized.size() * 2 + 1);

          IFDEBUG {

            DEBUGF(stderr, "tokens1: %lu   input size: %lu\n", tokenized.size(),
                   input.size());
            for (auto x : tokenized) {

              cerr << x << endl;

            }

          }

          for (auto token : tokenized) {

            string::const_iterator c = token.begin(), e = token.end(), f, p;
            smatch                 m;

            while (regex_search(c, e, m, regex_word)) {

              p = c;
              f = m[0].first;
              c = m[0].second;
              if (p < f) {

                // there are items between search start and find
                while (p < f) {

                  IFDEBUG {

                    string foo(p, p + 1);
                    DEBUGF(stderr, "before string: \"%s\"\n", foo.c_str());

                  }

                  tokens.push_back(std::string(p, p + 1));
                  ++p;

                }

                IFDEBUG {

                  string foo(p, f);
                  DEBUGF(stderr, "before string: \"%s\"\n", foo.c_str());
                  tokens.push_back(std::string(p, f));

                }

              }

              DEBUGF(stderr,
                     "SUBstring \"%s\" found at start %lu offset %lu continue "
                     "at %lu\n",
                     m[0].str().c_str(), p - input.begin(), m.position(),
                     c - token.begin());
              tokens.push_back(m[0].str());

            }

            if (c < e) {

              while (c < e) {

                IFDEBUG {

                  string foo(c, c + 1);
                  DEBUGF(stderr, "after string: \"%s\"\n", foo.c_str());

                }

                tokens.push_back(std::string(c, c + 1));
                ++c;

              }

              IFDEBUG {

                string foo(c, e);
                DEBUGF(stderr, "after string: \"%s\"\n", foo.c_str());

              }

              tokens.push_back(std::string(c, e));

            }

          }

        }

        tokens.push_back(string(match_begin, match_end));

      }

      if (cur < ende) {

        sregex_token_iterator it{cur, ende, regex_whitespace, -1};
        vector<std::string>   tokenized{it, {}};
        tokenized.erase(
            std::remove_if(tokenized.begin(), tokenized.end(),
                           [](std::string const &s) { return s.size() == 0; }),
            tokenized.end());
        tokens.reserve(tokens.size() + tokenized.size() * 2 + 1);

        IFDEBUG {

          DEBUGF(stderr, "tokens2: %lu   input size: %lu\n", tokenized.size(),
                 input.size());
          for (auto x : tokenized) {

            cerr << x << endl;

          }

        }

        for (auto token : tokenized) {

          string::const_iterator c = token.begin(), e = token.end(), f, p;
          smatch                 m;

          while (regex_search(c, e, m, regex_word)) {

            p = c;
            f = m[0].first;
            c = m[0].second;
            if (p < f) {

              // there are items between search start and find
              while (p < f) {

                IFDEBUG {

                  string foo(p, p + 1);
                  DEBUGF(stderr, "before string: \"%s\"\n", foo.c_str());

                }

                tokens.push_back(std::string(p, p + 1));
                ++p;

              }

              IFDEBUG {

                string foo(p, f);
                DEBUGF(stderr, "before string: \"%s\"\n", foo.c_str());

              }

              tokens.push_back(std::string(p, f));

            }

            DEBUGF(stderr,
                   "SUB2string \"%s\" found at start %lu offset %lu continue "
                   "at %lu\n",
                   m[0].str().c_str(), p - input.begin(), m.position(),
                   c - token.begin());
            tokens.push_back(m[0].str());

          }

          if (c < e) {

            while (c < e) {

              IFDEBUG {

                string foo(c, c + 1);
                DEBUGF(stderr, "after string: \"%s\"\n", foo.c_str());

              }

              tokens.push_back(std::string(c, c + 1));
              ++c;

            }

            IFDEBUG {

              string foo(c, e);
              DEBUGF(stderr, "after string: \"%s\"\n", foo.c_str());

            }

            tokens.push_back(std::string(c, e));

          }

        }

      }

    }

    IFDEBUG {

      DEBUGF(stderr, "DUMPING TOKENS:\n");
      u32 size_1 = tokens.size() - 1;
      for (u32 i = 0; i < tokens.size(); ++i) {

        DEBUGF(stderr, "%s", tokens[i].c_str());
        if (unlikely(alternative_tokenize && i < size_1)) {

          DEBUGF(stderr, "%s", whitespace.c_str());

        }

      }

      DEBUGF(stderr, "---------------------------\n");

    }

    if (tokens.size() < AUTOTOKENS_SIZE_MIN) {

      file_mapping[fn] = NULL;
      s = NULL;
      DEBUGF(stderr, "too few tokens\n");
      return 0;

    }

    /* Now we transform the tokens into an ID list and saved that */

    structure = new vector<u32>();
    u32 id;

    for (u32 i = 0; i < tokens.size(); ++i) {

      if ((id = token_to_id[tokens[i]]) == 0) {

        // First time we see this token, add it to the list
        token_to_id[tokens[i]] = current_id;
        id_to_token[current_id] = tokens[i];
        structure->push_back(current_id);
        ++current_id;

      } else {

        structure->push_back(id);

      }

    }

    // save the token structure to the file mapping
    file_mapping[fn] = structure;
    id_mapping[valid_structures] = structure;
    ++valid_structures;
    s = structure;
    all_structure_items += structure->size();

    // we are done!
    DEBUGF(stderr, "DONE! We have %lu tokens in the structure\n",
           structure->size());

  }

  else {

    if (entry->second == NULL) {

      DEBUGF(stderr, "Skipping %s\n", filename);
      s = NULL;
      return 0;

    }

    s = entry->second;
    DEBUGF(stderr, "OK %s\n", filename);

  }

  return 1;  // we always fuzz unless non-ascii or too small

}

extern "C" my_mutator_t *afl_custom_init(afl_state *afl, unsigned int seed) {

  (void)(seed);
  my_mutator_t *data = (my_mutator_t *)calloc(1, sizeof(my_mutator_t));
  if (!data) {

    perror("afl_custom_init alloc");
    return NULL;

  }

  if (getenv("AUTOTOKENS_DEBUG")) { debug = 1; }
  if (getenv("AUTOTOKENS_ONLY_FAV")) { only_fav = 1; }
  if (getenv("AUTOTOKENS_ALTERNATIVE_TOKENIZE")) { alternative_tokenize = 1; }
  if (getenv("AUTOTOKENS_WHITESPACE")) {

    whitespace = getenv("AUTOTOKENS_WHITESPACE");

  }

  if (getenv("AUTOTOKENS_COMMENT")) {

    char buf[256];
    snprintf(buf, sizeof(buf), "(%s.*)([\r\n]?)", getenv("AUTOTOKENS_COMMENT"));
    regex_comment_custom = new regex(buf, regex::optimize);

  }

  data->afl = afl_ptr = afl;

  // set common whitespace tokens
  // we deliberately do not put uncommon ones here to these will count as
  // identifier tokens.
  if (!alternative_tokenize) {

    token_to_id[" "] = current_id;
    id_to_token[current_id] = " ";
    ++current_id;
    token_to_id["\t"] = current_id;
    id_to_token[current_id] = "\t";
    ++current_id;
    token_to_id["\n"] = current_id;
    id_to_token[current_id] = "\n";
    ++current_id;
    token_to_id["\r\n"] = current_id;
    id_to_token[current_id] = "\r\n";
    ++current_id;
    token_to_id[" \n"] = current_id;
    id_to_token[current_id] = " \n";
    ++current_id;
    token_to_id["  "] = current_id;
    id_to_token[current_id] = "  ";
    ++current_id;
    token_to_id["\t\t"] = current_id;
    id_to_token[current_id] = "\t\t";
    ++current_id;
    token_to_id["\n\n"] = current_id;
    id_to_token[current_id] = "\n\n";
    ++current_id;
    token_to_id["\r\n\r\n"] = current_id;
    id_to_token[current_id] = "\r\n\r\n";
    ++current_id;
    token_to_id["    "] = current_id;
    id_to_token[current_id] = "    ";
    ++current_id;
    token_to_id["\t\t\t\t"] = current_id;
    id_to_token[current_id] = "\t\t\t\t";
    ++current_id;
    token_to_id["\n\n\n\n"] = current_id;
    id_to_token[current_id] = "\n\n\n\n";
    ++current_id;
    whitespace_ids = current_id;
    token_to_id["\""] = current_id;
    id_to_token[current_id] = "\"";
    ++current_id;
    token_to_id["'"] = current_id;
    id_to_token[current_id] = "'";
    ++current_id;

  }

  return data;

}

extern "C" void afl_custom_splice_optout(my_mutator_t *data) {

  (void)(data);

}

extern "C" void afl_custom_deinit(my_mutator_t *data) {

  /* we use this to print statistics at exit :-)
     needs to be stderr as stdout is filtered */

  fprintf(stderr,
          "\n\nAutotoken mutator statistics:\n"
          "  Number of all seen tokens:  %u\n"
          "  Number of input structures: %u\n"
          "  Number of all items in structures: %llu\n"
          "  Number of total fuzzes: %llu\n\n",
          current_id - 1, valid_structures, all_structure_items, fuzz_count);

  free(data);

}


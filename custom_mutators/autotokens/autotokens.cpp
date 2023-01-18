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

using namespace std;

typedef struct my_mutator {

  afl_state *afl;

} my_mutator_t;

#define DEBUG \
  if (unlikely(debug)) fprintf

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
static unordered_map<string, vector<u32> *> file_mapping;
static unordered_map<string, u32>           token_to_id;
static unordered_map<u32, string>           id_to_token;
static string                               whitespace = AUTOTOKENS_WHITESPACE;
static regex                               *regex_comment_custom;
static regex regex_comment_star("/\\*([:print:]|\n)*?\\*/",
                                regex::multiline | regex::optimize);
static regex regex_word("[A-Za-z0-9_$]+", regex::optimize);
static regex regex_whitespace(R"([ \t]+)", regex::optimize);
static regex regex_string("\"[[:print:]]*?\"|'[[:print:]]*?'", regex::optimize);
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
  // DEBUG(stderr, "structure size: %lu, rounds: %u \n", m.size(), rounds);

  u32 max_rand = 7;

  for (i = 0; i < rounds; ++i) {

    switch (rand_below(afl_ptr, max_rand)) {

      /* CHANGE */
      case 0 ... 3:                                         /* fall through */
      {

        u32 pos = rand_below(afl_ptr, m_size);
        u32 cur_item = m[pos], new_item;
        do {

          new_item = rand_below(afl_ptr, current_id);

        } while (unlikely(

            new_item == cur_item ||
            (!alternative_tokenize &&
             ((whitespace_ids < new_item && whitespace_ids >= cur_item) ||
              (whitespace_ids >= new_item && whitespace_ids < cur_item)))));

        DEBUG(stderr, "MUT: %u -> %u\n", cur_item, new_item);
        m[pos] = new_item;
        break;

      }

      /* INSERT (m_size +1 so we insert also after last place) */
      case 4 ... 5: {

        u32 new_item;
        do {

          new_item = rand_below(afl_ptr, current_id);

        } while (new_item >= whitespace_ids);

        u32 pos = rand_below(afl_ptr, m_size + 1);
        m.insert(m.begin() + pos, new_item);
        ++m_size;

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

      /* ERASE - only if large enough */
      case 6: {

        if (m_size > 8) {

          m.erase(m.begin() + rand_below(afl_ptr, m_size));
          --m_size;

        } else {

          max_rand = 6;

        }

        break;

      }

        // TODO: add full line insert splice, replace splace, delete

    }

  }

  string output;
  u32    m_size_1 = m_size - 1;

  for (i = 0; i < m_size; ++i) {

    output += id_to_token[m[i]];
    if (unlikely(alternative_tokenize && i < m_size_1)) {

      output += whitespace;

    }

  }

  u32 mutated_size = output.size();
  u8 *mutated_out = (u8 *)afl_realloc((void **)out_buf, mutated_size);

  if (unlikely(!mutated_out)) {

    *out_buf = NULL;
    return 0;

  }

  if (unlikely(debug)) {

    DEBUG(stderr, "MUTATED to %u bytes:\n", mutated_size);
    fwrite(output.data(), 1, mutated_size, stderr);
    DEBUG(stderr, "\n---\n");

  }

  memcpy(mutated_out, output.data(), mutated_size);
  *out_buf = mutated_out;
  return mutated_size;

}

/* We are not using afl_custom_queue_new_entry() because not every corpus entry
   will be necessarily fuzzed. so we use afl_custom_queue_get() instead */

extern "C" unsigned char afl_custom_queue_get(void                *data,
                                              const unsigned char *filename) {

  if (likely(!debug)) {

    if ((afl_ptr->shm.cmplog_mode && !afl_ptr->queue_cur->is_ascii) ||
        (only_fav && !afl_ptr->queue_cur->favored)) {

      s = NULL;
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
      DEBUG(stderr, "Added from dictionary: \"%s\"\n", ptr);

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
      DEBUG(stderr, "Added from auto dictionary: \"%s\"\n", ptr);

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
      DEBUG(stderr, "Too short (%lu) %s\n", len, filename);
      s = NULL;
      return 0;

    }

    string input;
    input.resize(len);
    rewind(fp);
    fread((void *)input.data(), input.size(), 1, fp);
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
        DEBUG(stderr, "Not text (%lu) %s\n", len, filename);
        s = NULL;
        return 0;

      }

    }

    // DEBUG(stderr, "Read %lu bytes for %s\nBefore comment trim:\n%s\n",
    // input.size(), filename, input.c_str());

    if (regex_comment_custom) {

      input = regex_replace(input, *regex_comment_custom, "$2");

    } else {

      input = regex_replace(input, regex_comment_star, "");

    }

    DEBUG(stderr, "After replace %lu bytes for %s\n%s\n", input.size(),
          filename, input.c_str());

    u32  spaces = count(input.begin(), input.end(), ' ');
    u32  tabs = count(input.begin(), input.end(), '\t');
    u32  linefeeds = count(input.begin(), input.end(), '\n');
    bool ends_with_linefeed = input[input.length() - 1] == '\n';
    DEBUG(stderr, "spaces=%u tabs=%u linefeeds=%u ends=%u\n", spaces, tabs,
          linefeeds, ends_with_linefeed);
    all_spaces += spaces;
    all_tabs += tabs;
    all_lf += linefeeds;
    all_ws = all_spaces + all_tabs + all_lf;

    // now extract all tokens
    vector<string>         tokens;
    smatch                 match;
    string::const_iterator cur = input.begin(), ende = input.end(), found, prev;

    DEBUG(stderr, "START!\n");

    if (likely(!alternative_tokenize)) {

      while (regex_search(cur, ende, match, regex_string,
                          regex_constants::match_any |
                              regex_constants::match_not_null |
                              regex_constants::match_continuous)) {

        prev = cur;
        found = match[0].first;
        cur = match[0].second;
        DEBUG(stderr,
              "string %s found at start %lu offset %lu continue at %lu\n",
              match[0].str().c_str(), prev - input.begin(), match.position(),
              cur - input.begin());

        if (prev < found) {  // there are items between search start and find
          while (prev < found) {

            if (isspace(*prev)) {

              auto start = prev;
              while (isspace(*prev)) {

                ++prev;

              }

              tokens.push_back(std::string(start, prev));
              DEBUG(stderr, "WHITESPACE %ld \"%s\"\n", prev - start,
                    tokens[tokens.size() - 1].c_str());

            } else if (isalnum(*prev) || *prev == '$' || *prev == '_') {

              auto start = prev;
              while (isalnum(*prev) || *prev == '$' || *prev == '_' ||
                     *prev == '.' || *prev == '/') {

                ++prev;

              }

              tokens.push_back(std::string(start, prev));
              DEBUG(stderr, "IDENTIFIER %ld \"%s\"\n", prev - start,
                    tokens[tokens.size() - 1].c_str());

            } else {

              tokens.push_back(std::string(prev, prev + 1));
              DEBUG(stderr, "OTHER \"%c\"\n", *prev);
              ++prev;

            }

          }

        }

        if (match[0].length() > 0) { tokens.push_back(match[0]); }

      }

      DEBUG(stderr, "AFTER all strings\n");

      if (cur < ende) {

        while (cur < ende) {

          if (isspace(*cur)) {

            auto start = cur;
            while (isspace(*cur)) {

              ++cur;

            }

            tokens.push_back(std::string(start, cur));
            DEBUG(stderr, "WHITESPACE %ld \"%s\"\n", cur - start,
                  tokens[tokens.size() - 1].c_str());

          } else if (isalnum(*cur) || *cur == '$' || *cur == '_') {

            auto start = cur;
            while (isalnum(*cur) || *cur == '$' || *cur == '_' || *cur == '.' ||
                   *cur == '/') {

              ++cur;

            }

            tokens.push_back(std::string(start, cur));
            DEBUG(stderr, "IDENTIFIER %ld \"%s\"\n", cur - start,
                  tokens[tokens.size() - 1].c_str());

          } else {

            tokens.push_back(std::string(cur, cur + 1));
            DEBUG(stderr, "OTHER \"%c\"\n", *cur);
            ++cur;

          }

        }

      }

    } else {

      // alternative tokenize

      while (regex_search(cur, ende, match, regex_string)) {

        prev = cur;
        found = match[0].first;
        cur = match[0].second;
        DEBUG(stderr,
              "string %s found at start %lu offset %lu continue at %lu\n",
              match[0].str().c_str(), prev - input.begin(), match.position(),
              cur - input.begin());
        if (prev < found) {  // there are items between search start and find
          sregex_token_iterator it{prev, found, regex_whitespace, -1};
          vector<std::string>   tokenized{it, {}};
          tokenized.erase(std::remove_if(tokenized.begin(), tokenized.end(),
                                         [](std::string const &s) {

                                           return s.size() == 0;

                                         }),

                          tokenized.end());
          tokens.reserve(tokens.size() + tokenized.size() * 2 + 1);

          if (unlikely(debug)) {

            DEBUG(stderr, "tokens: %lu   input size: %lu\n", tokenized.size(),
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

                  if (unlikely(debug)) {

                    string foo(p, p + 1);
                    DEBUG(stderr, "before string: \"%s\"\n", foo.c_str());

                  }

                  tokens.push_back(std::string(p, p + 1));
                  ++p;

                }

                /*
                                string foo(p, f);
                                DEBUG(stderr, "before string: \"%s\"\n",
                   foo.c_str()); tokens.push_back(std::string(p, f));
                */

              }

              DEBUG(
                  stderr,
                  "SUBstring \"%s\" found at start %lu offset %lu continue at "
                  "%lu\n",
                  m[0].str().c_str(), p - input.begin(), m.position(),
                  c - token.begin());
              tokens.push_back(m[0].str());

            }

            if (c < e) {

              while (c < e) {

                if (unlikely(debug)) {

                  string foo(c, c + 1);
                  DEBUG(stderr, "after string: \"%s\"\n", foo.c_str());

                }

                tokens.push_back(std::string(c, c + 1));
                ++c;

              }

              /*
                            if (unlikely(debug)) {

                              string foo(c, e);
                              DEBUG(stderr, "after string: \"%s\"\n",
                 foo.c_str());

                            }

                            tokens.push_back(std::string(c, e));
              */

            }

          }

        }

        if (match[0].length() > 0) { tokens.push_back(match[0]); }

      }

      if (cur < ende) {

        sregex_token_iterator it{cur, ende, regex_whitespace, -1};
        vector<std::string>   tokenized{it, {}};
        tokenized.erase(
            std::remove_if(tokenized.begin(), tokenized.end(),
                           [](std::string const &s) { return s.size() == 0; }),
            tokenized.end());
        tokens.reserve(tokens.size() + tokenized.size() * 2 + 1);

        if (unlikely(debug)) {

          DEBUG(stderr, "tokens: %lu   input size: %lu\n", tokenized.size(),
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

                if (unlikely(debug)) {

                  string foo(p, p + 1);
                  DEBUG(stderr, "before string: \"%s\"\n", foo.c_str());

                }

                tokens.push_back(std::string(p, p + 1));
                ++p;

              }

              /*
                            if (unlikely(debug)) {

                              string foo(p, f);
                              DEBUG(stderr, "before string: \"%s\"\n",
                 foo.c_str());

                            }

                            tokens.push_back(std::string(p, f));
              */

            }

            DEBUG(stderr,
                  "SUB2string \"%s\" found at start %lu offset %lu continue at "
                  "%lu\n",
                  m[0].str().c_str(), p - input.begin(), m.position(),
                  c - token.begin());
            tokens.push_back(m[0].str());

          }

          if (c < e) {

            while (c < e) {

              if (unlikely(debug)) {

                string foo(c, c + 1);
                DEBUG(stderr, "after string: \"%s\"\n", foo.c_str());

              }

              tokens.push_back(std::string(c, c + 1));
              ++c;

            }

            /*
                        if (unlikely(debug)) {

                          string foo(c, e);
                          DEBUG(stderr, "after string: \"%s\"\n", foo.c_str());

                        }

                        tokens.push_back(std::string(c, e));
            */

          }

        }

      }

    }

    if (unlikely(debug)) {

      DEBUG(stderr, "DUMPING TOKENS:\n");
      u32 size_1 = tokens.size() - 1;
      for (u32 i = 0; i < tokens.size(); ++i) {

        DEBUG(stderr, "%s", tokens[i].c_str());
        if (unlikely(alternative_tokenize && i < size_1)) {

          DEBUG(stderr, "%s", whitespace.c_str());

        }

      }

      DEBUG(stderr, "---------------------------\n");

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
    s = structure;
    ++valid_structures;
    all_structure_items += structure->size();

    // we are done!
    DEBUG(stderr, "DONE! We have %lu tokens in the structure\n",
          structure->size());

  } else {

    if (entry->second == NULL) {

      DEBUG(stderr, "Skipping %s\n", filename);
      s = NULL;
      return 0;

    }

    s = entry->second;
    DEBUG(stderr, "OK %s\n", filename);

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

  return data;

}

extern "C" void afl_custom_deinit(my_mutator_t *data) {

  /* we use this to print statistics at exit :-)
     needs to be stderr as stdout is filtered */

  fprintf(stderr,
          "\n\nAutotoken mutator statistics:\n"
          "  Number of all seen tokens:  %lu\n"
          "  Number of input structures: %lu\n"
          "  Number of all items in structures: %lu\n\n",
          current_id - 1, valid_structures, all_structure_items);

  free(data);

}


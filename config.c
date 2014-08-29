#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include "header.h"
#include <errno.h>
#include <ctype.h>
#include <libgen.h>
#include <wordexp.h>
#include <dirent.h>
static int get_line(char **result, size_t * result_len, FILE * f, int *line);
static char *next_word(char *buf, char *word, int maxlen);
static address_family *get_address_family(address_family * af[], char *name);
static method *get_method(address_family * af, char *name);
allowup_defn *get_allowup(allowup_defn ** allowups, char *name);

allowup_defn *add_allow_up(char *filename, int line,
    allowup_defn * allow_up, char *iface_name);

variable *set_variable(char *filename, char *name, char *value,
    variable ** var, int *n_vars, int *max_vars)
{
    /*
     * if name ends with '?', don't update
     * the variable if it already exists
     */
    bool dont_update = false;

    size_t len = strlen(name);

    if (name[len - 1] == '?') {
        dont_update = true;
        len--;
    }
    if (strcmp(name, "pre-up") != 0 && strcmp(name, "up") != 0 && strcmp(name, "down") != 0 && strcmp(name, "post-down") != 0) {
        int j;
        for (j = 0; j < *n_vars; j++) {
            if (strncmpz(name, (*var)[j].name, len) == 0) {
                if (dont_update) {
                    return NULL;
                }

                if ((*var)[j].value == value) {
                    return &(*var)[j];
                }

                free((*var)[j].value);
                (*var)[j].value = strdup(value);
                if (!(*var)[j].value) {
                    perror(filename);
                    return NULL;
                }

                return &((*var)[j]);
            }
        }
    }

    if (*n_vars >= *max_vars) {
        variable *new_var;
        *max_vars += 10;
        new_var = realloc(*var, sizeof(variable) * *max_vars);
        if (new_var == NULL) {
            perror(filename);
            return NULL;
        }
        *var = new_var;
    }

    (*var)[*n_vars].name = strndup(name, len);
    (*var)[*n_vars].value = strdup(value);

    if (!(*var)[*n_vars].name) {
        perror(filename);
        return NULL;
    }

    if (!(*var)[*n_vars].value) {
        perror(filename);
        return NULL;
    }

    (*n_vars)++;
    return &((*var)[(*n_vars) - 1]);
}

void convert_variables(char *filename, conversion * conversions, interface_defn * ifd)
{
    conversion *c;
    for (c = conversions; c && c->option && c->fn; c++) {
        if (strcmp(c->option, "iface") == 0) {
            if (c->newoption) {
                variable *o = set_variable(filename, c->newoption, ifd->real_iface,
                    &ifd->option, &ifd->n_options, &ifd->max_options);
                if (o)
                    c->fn(ifd, &o->value, c->argc, c->argv);
                continue;
            }
        }

        int j;
        for (j = 0; j < ifd->n_options; j++) {
            if (strcmp(ifd->option[j].name, c->option) == 0) {
                if (c->newoption) {
                    variable *o = set_variable(filename, c->newoption, ifd->option[j].value,
                        &ifd->option, &ifd->n_options, &ifd->max_options);
                    if (o)
                        c->fn(ifd, &o->value, c->argc, c->argv);
                } else {
                    variable *o = &(ifd->option[j]);
                    c->fn(ifd, &o->value, c->argc, c->argv);
                }
            }
        }
    }
}

interfaces_file *read_interfaces(char *filename)
{
    interfaces_file *defn;

    defn = malloc(sizeof(interfaces_file));
    if (defn == NULL) {
        return NULL;
    }
    defn->allowups = NULL;
    defn->mappings = NULL;
    defn->ifaces = NULL;

    if (!no_loopback) {
        interface_defn *lo_if = malloc(sizeof(interface_defn));
        if (!lo_if) {

            perror(filename);
            return NULL;
        }

        *lo_if = (interface_defn) {
            .logical_iface = strdup(LO_IFACE),
            .max_options = 0,
            .address_family = &addr_inet,
            .method = get_method(&addr_inet, "loopback"),
            .n_options = 0,
            .option = NULL,
            .next = NULL
        };

        defn->ifaces = lo_if;

        add_allow_up(__FILE__, __LINE__, get_allowup(&defn->allowups, "auto"), lo_if->logical_iface);
    }
    return read_interfaces_defn(defn, filename);
}

static int directory_filter(const struct dirent * d)
{
    const char *p;
    if ((d == NULL) || (d->d_name == NULL)) {
        return 0;
    }
    for (p = d->d_name; *p; p++) {
        if (!(((*p >= 'a') && (*p <= 'z')) ||
              ((*p >= 'A') && (*p <= 'Z')) ||
              ((*p >= '0') && (*p <= '9')) ||
              (*p == '_') || (*p == '-')))
            return 0;
    }
    return 1;
}

interfaces_file *read_interfaces_defn(interfaces_file * defn, char *filename)
{
    FILE *f;
    int line;
    char *buf = NULL;
    size_t buf_len = 0;
    interface_defn *currif = NULL;
    mapping_defn *currmap = NULL;
    enum { NONE, IFACE, MAPPING } currently_processing = NONE;
    char firstword[80];
    char *rest;

    f = fopen(filename, "r");
    if (f == NULL)
        return NULL;
    line = 0;

    while (get_line(&buf, &buf_len, f, &line)) {
        rest = next_word(buf, firstword, 80);
        if (rest == NULL)
            continue;           /* blank line */

        if (strcmp(firstword, "mapping") == 0) {
            currmap = malloc(sizeof(mapping_defn));
            if (currmap == NULL) {
                perror(filename);
                return NULL;
            }
            currmap->max_matches = 0;
            currmap->n_matches = 0;
            currmap->match = NULL;

            while ((rest = next_word(rest, firstword, 80))) {
                if (currmap->max_matches == currmap->n_matches) {
                    char **tmp;
                    currmap->max_matches = currmap->max_matches * 2 + 1;
                    tmp = realloc(currmap->match, sizeof(*tmp) * currmap->max_matches);
                    if (tmp == NULL) {
                        currmap->max_matches = (currmap->max_matches - 1) / 2;
                        perror(filename);
                        return NULL;
                    }
                    currmap->match = tmp;
                }

                currmap->match[currmap->n_matches++] = strdup(firstword);
            }
            currmap->script = NULL;

            currmap->max_mappings = 0;
            currmap->n_mappings = 0;
            currmap->mapping = NULL;
            {
                mapping_defn **where = &defn->mappings;
                while (*where != NULL) {
                    where = &(*where)->next;
                }
                *where = currmap;
                currmap->next = NULL;
            }
            currently_processing = MAPPING;
        } else if (strcmp(firstword, "source") == 0) {
            char *filename_dup = strdup(filename);
            if (filename_dup == NULL) {
                perror(filename);
                return NULL;
            }
            char *dir = strdup(dirname(filename_dup));
            if (dir == NULL) {
                perror(filename);
                return NULL;
            }
            free(filename_dup);

            size_t l = strlen(dir);
            char * pattern;
            if (rest[0] == '/') {
                size_t s = strlen(rest) + 1; /* + NUL */
                pattern = malloc(s);
                if (pattern == NULL) {
                    perror(filename);
                    return NULL;
                }
                pattern[0] = '\0';
            } else {
                size_t s = l + strlen(rest) + 2; /* + slash + NUL */
                pattern = malloc(s);
                if (pattern == NULL) {
                    perror(filename);
                    return NULL;
                }
                pattern[0] = '\0';
                strcat(pattern, dir);
                strcat(pattern, "/");
            }
            strcat(pattern, rest);

            wordexp_t p;
            char **w;
            size_t i;
            int fail = wordexp(pattern, &p, WRDE_NOCMD);
            if (!fail) {
                w = p.we_wordv;
                for (i = 0; i < p.we_wordc; i++) {
                    if (verbose) {
                        fprintf(stderr, "Parsing file %s\n", w[i]);
                    }
                    read_interfaces_defn(defn, w[i]);
                }
                wordfree(&p);
            }
            free(pattern);
            free(dir);
            currently_processing = NONE;
        } else if (strlmatch(firstword, "source-dir") == 0) {
            char *filename_dup = strdup(filename);
            if (filename_dup == NULL) {
                perror(filename);
                return NULL;
            }
            char *dir = strdup(dirname(filename_dup));
            if (dir == NULL) {
                perror(filename);
                return NULL;
            }
            free(filename_dup);

            size_t l = strlen(dir);
            char * pattern;
            if (rest[0] == '/') {
                size_t s = strlen(rest) + 1; /* + NUL */
                pattern = malloc(s);
                if (pattern == NULL) {
                    perror(filename);
                    return NULL;
                }
                pattern[0] = '\0';
            } else {
                size_t s = l + strlen(rest) + 2; /* + slash + NUL */
                pattern = malloc(s);
                if (pattern == NULL) {
                    perror(filename);
                    return NULL;
                }
                pattern[0] = '\0';
                strcat(pattern, dir);
                strcat(pattern, "/");
            }
            strcat(pattern, rest);

            wordexp_t p;
            char **w;
            size_t i;
            int fail = wordexp(pattern, &p, WRDE_NOCMD);
            if (!fail) {
                w = p.we_wordv;
                for (i = 0; i < p.we_wordc; i++) {
                    struct dirent **namelist;
                    int n = scandir(w[i], &namelist, directory_filter, alphasort);
                    if (n >= 0) {
                        if (verbose) {
                            fprintf(stderr, "Reading directory %s\n", w[i]);
                        }

                        int j;
                        size_t ll = strlen(w[i]);
                        for (j = 0; j < n; j++) {
                            size_t s = ll + strlen(namelist[j]->d_name) + 2; /* + slash + NUL */
                            char *name = malloc(s);
                            if (name == NULL) {
                                perror(filename);
                                return NULL;
                            }
                            name[0] = '\0';
                            strcat(name, w[i]);
                            strcat(name, "/");
                            strcat(name, namelist[j]->d_name);

                            if (verbose) {
                                fprintf(stderr, "Parsing file %s\n", name);
                            }
                            read_interfaces_defn(defn, name);
                            free(name);
                        }
                        free(namelist);
                    }
                }
                wordfree(&p);
            }
            free(pattern);
            free(dir);
            currently_processing = NONE;
        } else if (strcmp(firstword, "iface") == 0) {
            {
                char iface_name[80];
                char address_family_name[80];
                char method_name[80];

                currif = malloc(sizeof(interface_defn));
                if (!currif) {
                    perror(filename);
                    return NULL;
                }

                rest = next_word(rest, iface_name, 80);
                rest = next_word(rest, address_family_name, 80);
                rest = next_word(rest, method_name, 80);

                if (rest == NULL) {
                    fprintf(stderr, "%s:%d: too few parameters for iface line\n", filename, line);
                    return NULL;
                }

                if (rest[0] != '\0') {
                    fprintf(stderr, "%s:%d: too many parameters for iface line\n", filename, line);
                    return NULL;
                }

                currif->logical_iface = strdup(iface_name);
                if (!currif->logical_iface) {
                    perror(filename);
                    return NULL;
                }
                currif->address_family = get_address_family(addr_fams, address_family_name);
                if (!currif->address_family) {
                    fprintf(stderr, "%s:%d: unknown address type\n", filename, line);
                    return NULL;
                }
                currif->method = get_method(currif->address_family, method_name);
                if (!currif->method) {
                    fprintf(stderr, "%s:%d: unknown method\n", filename, line);
                    return NULL;        /* FIXME */
                }
                currif->automatic = 1;
                currif->max_options = 0;
                currif->n_options = 0;
                currif->option = NULL;

                {
                    interface_defn **where = &defn->ifaces;
                    while (*where != NULL) {
                        where = &(*where)->next;
                    }

                    *where = currif;
                    currif->next = NULL;
                }
            }
            currently_processing = IFACE;
        } else if (strcmp(firstword, "auto") == 0) {
            allowup_defn *auto_ups = get_allowup(&defn->allowups, "auto");
            if (!auto_ups) {
                perror(filename);
                return NULL;
            }
            while ((rest = next_word(rest, firstword, 80))) {
                if (!add_allow_up(filename, line, auto_ups, firstword))
                    return NULL;
            }
            currently_processing = NONE;
        } else if (strncmp(firstword, "allow-", 6) == 0 && strlen(firstword) > 6) {
            allowup_defn *allow_ups = get_allowup(&defn->allowups, firstword + 6);
            if (!allow_ups) {
                perror(filename);
                return NULL;
            }
            while ((rest = next_word(rest, firstword, 80))) {
                if (!add_allow_up(filename, line, allow_ups, firstword))
                    return NULL;
            }
            currently_processing = NONE;
        } else {
            switch (currently_processing) {
                case IFACE:
                    if (strcmp(firstword, "post-up") == 0) {
                        strcpy(firstword, "up");
                    }
                    if (strcmp(firstword, "pre-down") == 0) {
                        strcpy(firstword, "down");
                    }
                    {
                        int i;

                        if (strlen(rest) == 0) {
                            fprintf(stderr, "%s:%d: option with empty value\n", filename, line);
                            return NULL;
                        }

                        if (strcmp(firstword, "pre-up") != 0 && strcmp(firstword, "up") != 0 && strcmp(firstword, "down") != 0 && strcmp(firstword, "post-down") != 0) {
                            for (i = 0; i < currif->n_options; i++) {
                                if (strcmp(currif->option[i].name, firstword) == 0) {
                                    size_t l = strlen(currif->option[i].value);
                                    currif->option[i].value = realloc(currif->option[i].value, l + strlen(rest) + 2);   /* 2 for NL and NULL */
                                    if (!currif->option[i].value) {
                                        perror(filename);
                                        return NULL;
                                    }

                                    currif->option[i].value[l] = '\n';
                                    strcpy(&(currif->option[i].value[l + 1]), rest);
                                    rest = currif->option[i].value;
                                }
                            }
                        }
                    }
                    set_variable(filename, firstword, rest, &currif->option, &currif->n_options, &currif->max_options);
                    break;
                case MAPPING:
                    if (strcmp(firstword, "script") == 0) {
                        if (currmap->script != NULL) {
                            fprintf(stderr, "%s:%d: duplicate script in mapping\n", filename, line);
                            return NULL;
                        } else {
                            currmap->script = strdup(rest);
                        }
                    } else if (strcmp(firstword, "map") == 0) {
                        if (currmap->max_mappings == currmap->n_mappings) {
                            char **opt;
                            currmap->max_mappings = currmap->max_mappings * 2 + 1;
                            opt = realloc(currmap->mapping, sizeof(*opt) * currmap->max_mappings);
                            if (opt == NULL) {
                                perror(filename);
                                return NULL;
                            }
                            currmap->mapping = opt;
                        }
                        currmap->mapping[currmap->n_mappings] = strdup(rest);
                        currmap->n_mappings++;
                    } else {
                        fprintf(stderr, "%s:%d: misplaced option\n", filename, line);
                        return NULL;
                    }
                    break;
                case NONE:
                default:
                    fprintf(stderr, "%s:%d: misplaced option\n", filename, line);
                    return NULL;
            }
        }
    }
    if (ferror(f) != 0) {
        perror(filename);
        return NULL;
    }

    fclose(f);
    line = -1;

    return defn;
}

static int get_line(char **result, size_t * result_len, FILE * f, int *line)
{
    size_t pos;

    do {
        pos = 0;
        do {
            if (*result_len - pos < 10) {
                char *newstr = realloc(*result, *result_len * 2 + 80);
                if (newstr == NULL) {
                    return 0;
                }
                *result = newstr;
                *result_len = *result_len * 2 + 80;
            }
            if (!fgets(*result + pos, *result_len - pos, f)) {
                if (ferror(f) == 0 && pos == 0)
                    return 0;
                if (ferror(f) != 0)
                    return 0;
            }
            pos += strlen(*result + pos);
        } while (pos == *result_len - 1 && (*result)[pos - 1] != '\n');

        if (pos != 0 && (*result)[pos - 1] == '\n') {
            (*result)[--pos] = '\0';
        }

        (*line)++;

        assert((*result)[pos] == '\0');
        {
            int first = 0;
            while (isspace((*result)[first]) && (*result)[first]) {
                first++;
            }

            memmove(*result, *result + first, pos - first + 1);
            pos -= first;
        }
    } while ((*result)[0] == '#');

    while ((*result)[pos - 1] == '\\') {
        (*result)[--pos] = '\0';
        do {
            if (*result_len - pos < 10) {
                char *newstr = realloc(*result, *result_len * 2 + 80);
                if (newstr == NULL) {
                    return 0;
                }
                *result = newstr;
                *result_len = *result_len * 2 + 80;
            }
            if (!fgets(*result + pos, *result_len - pos, f)) {
                if (ferror(f) == 0 && pos == 0)
                    return 0;
                if (ferror(f) != 0)
                    return 0;
            }
            pos += strlen(*result + pos);
        } while (pos == *result_len - 1 && (*result)[pos - 1] != '\n');

        if (pos != 0 && (*result)[pos - 1] == '\n') {
            (*result)[--pos] = '\0';
        }

        (*line)++;

        assert((*result)[pos] == '\0');
    }

    while (isspace((*result)[pos - 1])) {       /* remove trailing whitespace */
        pos--;
    }
    (*result)[pos] = '\0';

    return 1;
}

static char *next_word(char *buf, char *word, int maxlen)
{
    if (!buf)
        return NULL;
    if (!*buf)
        return NULL;

    while (!isspace(*buf) && *buf) {
        if (maxlen-- > 1)
            *word++ = *buf;
        buf++;
    }
    if (maxlen > 0)
        *word = '\0';

    while (isspace(*buf) && *buf)
        buf++;

    return buf;
}

static address_family *get_address_family(address_family * af[], char *name)
{
    int i;
    for (i = 0; af[i]; i++) {
        if (strcmp(af[i]->name, name) == 0) {
            return af[i];
        }
    }
    return NULL;
}

static method *get_method(address_family * af, char *name)
{
    int i;
    for (i = 0; i < af->n_methods; i++) {
        if (strcmp(af->method[i].name, name) == 0) {
            return &af->method[i];
        }
    }
    return NULL;
}

allowup_defn *get_allowup(allowup_defn ** allowups, char *name)
{
    for (; *allowups; allowups = &(*allowups)->next) {
        if (strcmp((*allowups)->when, name) == 0)
            break;
    }
    if (*allowups == NULL) {
        *allowups = malloc(sizeof(allowup_defn));
        if (*allowups == NULL)
            return NULL;
        (*allowups)->when = strdup(name);
        (*allowups)->next = NULL;
        (*allowups)->max_interfaces = 0;
        (*allowups)->n_interfaces = 0;
        (*allowups)->interfaces = NULL;
    }
    return *allowups;
}

allowup_defn *find_allowup(interfaces_file * defn, char *name)
{
    allowup_defn *allowups = defn->allowups;
    for (; allowups; allowups = allowups->next) {
        if (strcmp(allowups->when, name) == 0)
            break;
    }
    return allowups;
}

allowup_defn *add_allow_up(char *filename, int line, allowup_defn * allow_up, char *iface_name)
{
    {
        int i;

        for (i = 0; i < allow_up->n_interfaces; i++) {
            if (strcmp(iface_name, allow_up->interfaces[i]) == 0) {
                return allow_up;
            }
        }
    }
    if (allow_up->n_interfaces == allow_up->max_interfaces) {
        char **tmp;
        allow_up->max_interfaces *= 2;
        allow_up->max_interfaces++;
        tmp = realloc(allow_up->interfaces, sizeof(*tmp) * allow_up->max_interfaces);
        if (tmp == NULL) {
            perror(filename);
            return NULL;
        }
        allow_up->interfaces = tmp;
    }

    allow_up->interfaces[allow_up->n_interfaces] = strdup(iface_name);
    allow_up->n_interfaces++;
    return allow_up;
}

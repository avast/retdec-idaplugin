
#include <string>

//--------------------------------------------------------------------------
// hex place methods

typedef hex_place_t hp_t;

//--------------------------------------------------------------------------
// Short information about the current location.
// It will be displayed in the status line
void ida_export hex_place_t__print(const hp_t *place, qstring *res, void *ud)
{
  std::string s = "hello @ "
      + std::to_string(place->y)
      + ":" + std::to_string(place->x);
  *res = s.c_str();
}

//--------------------------------------------------------------------------
// Convert current location to 'uval_t'
uval_t ida_export hex_place_t__touval(const hp_t *ths, void *)
{
  return ths->y;
}

//--------------------------------------------------------------------------
// Make a copy
place_t *ida_export hex_place_t__clone(const hp_t *ths)
{
  return new hp_t(*ths);
}

//--------------------------------------------------------------------------
// Copy from another hex_place_t object
void ida_export hex_place_t__copyfrom(hp_t *ths, const place_t *from)
{
  hp_t *s = (hp_t *)from;
  ths->d      = s->d;
  ths->y      = s->y;
  ths->x      = s->x;
  ths->lnnum  = s->lnnum;
}

//--------------------------------------------------------------------------
// Create a hex_place_t object at the specified address
// with the specified data
place_t *ida_export hex_place_t__makeplace(const hp_t *ths, void *, uval_t x, int lnnum)
{
  static hex_place_t p(nullptr, 0);
  p.d     = ths->d;
  p.y     = x;
  p.x     = 0;
  p.lnnum = lnnum;
  return &p;
}

//--------------------------------------------------------------------------
// Compare two hex_place_t objects
// Return -1, 0, 1
int ida_export hex_place_t__compare(const hp_t *ths, const place_t *t2)
{
  hp_t *s = (hp_t *)t2;
  // return compare(ths->y, s->y);

  if (ths->y == s->y)
  {
    return compare(ths->x, s->x);
  }
  else
  {
    return compare(ths->y, s->y);
  }
}

//--------------------------------------------------------------------------
// Check if the location data is correct and if not, adjust it
void ida_export hex_place_t__adjust(hp_t *ths, void *)
{
  if ( ths->y > ths->d->maxline() )
  {
    ths->y = 0;
    ths->x = 0;
    ths->lnnum = 0;
  }
}

//--------------------------------------------------------------------------
// Move to the previous location
bool ida_export hex_place_t__prev(hp_t *ths, void *)
{
  if ( ths->y == 0 )
    return false;
  ths->y--;
  return true;
}

//--------------------------------------------------------------------------
// Move to the next location
bool ida_export hex_place_t__next(hp_t *ths, void *)
{
  if ( ths->y >= ths->d->maxline() )
    return false;
  ths->y++;
  return true;
}

//--------------------------------------------------------------------------
// Are we at the beginning of the data?
bool ida_export hex_place_t__beginning(const hp_t *ths, void *)
{
  return ths->y == 0;
}

//--------------------------------------------------------------------------
// Are we at the end of the data?
bool ida_export hex_place_t__ending(const hp_t *ths, void *)
{
  return ths->y == ths->d->maxline();
}

//--------------------------------------------------------------------------
// Generate text for the current location
int ida_export hex_place_t__generate(
        const hp_t *ths,
        qstrvec_t *out,
        int *default_lnnum,
        color_t *,
        bgcolor_t *,
        void *,
        int maxsize)
{
  static unsigned cntr = 0;
  msg("[%d] generate() %d:%d\n", cntr++, ths->y, ths->x);

  int idx = ths->y;
  if ( idx > ths->d->maxline() || maxsize <= 0 )
    return 0;
  uint alignment = ths->d->alignment();
  uchar *data = (uchar *)qalloc(alignment);
  if ( !ths->d->read(alignment * ths->y, data, alignment) )
  {
    qfree(data);
    return 0;
  }

#define HEX_ASCII_SEP   2
  size_t bufsize = 4 * alignment + HEX_ASCII_SEP + 20;
  char *str = (char *)qalloc(bufsize);
  if ( str == NULL )
    nomem("hexplace");
  str[0] = 0;

  // add hex values
  static const char hexstr[] = "0123456789ABCDEF";
  size_t pos = qstrlen(str);
  for ( uint i = 0; i < alignment; i++ )
  {
    str[pos++] = ' ';
    uchar c = data[i];
    str[pos++] = hexstr[c >> 4];
    str[pos++] = hexstr[c & 0xF];
  }

  memset(&str[pos], ' ', HEX_ASCII_SEP);
  pos += HEX_ASCII_SEP;

  // add ascii values
  char *ptr = str + pos;
  char *end = str + bufsize;
  APPCHAR(ptr, end, COLOR_ON);
  APPCHAR(ptr, end, COLOR_NUMBER);
  for ( uint i = 0; i < alignment; i++ )
    APPCHAR(ptr, end, qisprint(data[i]) ? (char)data[i] : '.');
  APPCHAR(ptr, end, COLOR_OFF);
  APPCHAR(ptr, end, COLOR_NUMBER);
  APPZERO(ptr, end);

  qfree(data);
  out->push_back(str);
  *default_lnnum = 0;
  return 1;
}

//-------------------------------------------------------------------------
void ida_export hex_place_t__serialize(const hex_place_t *_this, bytevec_t *out)
{
  place_t__serialize(_this, out);
  append_ea(*out, _this->y);
  append_ea(*out, _this->x);
}

//-------------------------------------------------------------------------
bool ida_export hex_place_t__deserialize(hex_place_t *_this, const uchar **pptr, const uchar *end)
{
  if ( !place_t__deserialize(_this, pptr, end) || *pptr >= end )
    return false;
  _this->y = unpack_ea(pptr, end);
  _this->x = unpack_ea(pptr, end);
  return true;
}

//-------------------------------------------------------------------------
//lint -esym(843,hex_place_id) could be declared const
static int hex_place_id = -1;
static hex_place_t _template(nullptr, 0);
void register_hex_place()
{
  hex_place_id = register_place_class(&_template, PCF_EA_CAPABLE, &PLUGIN);
}

//-------------------------------------------------------------------------
int ida_export hex_place_t__id(const hex_place_t *)
{
  return hex_place_id;
}

//-------------------------------------------------------------------------
const char *ida_export hex_place_t__name(const hex_place_t *)
{
  return "hex_place_t";
}

//-------------------------------------------------------------------------
ea_t ida_export hex_place_t__toea(const hex_place_t *)
{
  return BADADDR;
}

//-------------------------------------------------------------------------
place_t *ida_export hex_place_t__enter(const hex_place_t *, uint32 *)
{
  return NULL;
}

//-------------------------------------------------------------------------
void ida_export hex_place_t__leave(const hex_place_t *, uint32)
{
}

//-------------------------------------------------------------------------
bool ida_export hex_place_t__rebase(hex_place_t *, const segm_move_infos_t &)
{
  return false;
}


#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <moves.hpp>

//==============================================================================

static int test_place_id = -1;

//==============================================================================

std::vector<std::string> text_ack =
{
	"int __cdecl ack(int a1, int a2)",
	"{",
	"  int v3; // eax",
	"",
	"  if ( !a1 )",
	"    return a2 + 1;",
	"  if ( !a2 )",
	"    return ack(a1 - 1, 1);",
	"  v3 = ack(a1, a2 - 1);",
	"  return ack(a1 - 1, v3);",
	"}",
};

std::vector<std::string> text_main =
{
	"int __cdecl main(int argc, const char **argv, const char **envp)",
	"{",
	"  int v4; // [esp+14h] [ebp-Ch]",
	"  int v5; // [esp+18h] [ebp-8h]",
	"  int v6; // [esp+1Ch] [ebp-4h]",
	"",
	"  v6 = 0;",
	"  v5 = 0;",
	"  v4 = 0;",
	"  __isoc99_scanf(\"%d %d\", &v5, &v4);",
	"  v6 = ack(v5, v4);",
	"  printf(\"ackerman( %d , %d ) = %d\n\", v5, v4, v6);",
	"  return v6;",
	"}",
};

//==============================================================================

struct Entry
{
	std::string body;
	ea_t addr;
	std::size_t x = 0;
};

using Line = std::vector<Entry>;
using Function = std::vector<Line>;

Function fnc_ack =
{
	{ {"int int __cdecl ack(int a1, int a2)", 0x804851C, 0} },
	{ {"{", 0x804851C, 0} },
	{ {"  int v3; // eax", 0x804851C, 0} },
	{ {"", 0x804851C, 0} },
	{ {"  if ( !a1 )", 0x8048526, 0} },
	{ {"    return a2 + 1;", 0x804852B, 0} },
	{ {"  if ( !a2 )", 0x8048534, 0} },
	{ {"    return ack(", 0x8048547, 0}, {"a1 - ", 0x8048544, 0}, {"1, ", 0x8048539, 0}, {"1);", 0x804853C, 0} },
	{ {"  v3 = ack(", 0x804855E, 0}, {"a1, ", 0x804855B, 0}, {"a2 - ", 0x8048554, 0}, {"1);", 0x8048551, 0} },
	{ {"  return ", 0x8048575, 0}, {"ack", 0x8048570, 0}, {"a1 - , ", 0x804856D, 0}, {"1, ", 0x8048566, 0}, {"v3);", 0x8048569, 0} },
	{ {"}", 0x8048575, 0} },
};

//==============================================================================

class test_data_t
{
	friend class test_place_t;

	private:
		Function& _data;
		std::map<ea_t, std::pair<std::size_t, std::size_t>> _addrs;

	public:
		test_data_t(Function& f) :
				_data(f)
		{
			std::size_t y = 0;
			for (auto& l : f)
			{
				std::size_t x = 0;

				for (auto& e : l)
				{
					if (_addrs.count(e.addr) == 0)
					{
						_addrs[e.addr] = {x, y};
					}
					e.x = x;
					x += e.body.size();
				}

				++y;
			}
		}

	public:
		uval_t min_line() const
		{
			return 1;
		}
		uval_t max_line() const
		{
			return _data.size();
		}

		ea_t min_ea() const
		{
			return _addrs.empty() ? BADADDR : _addrs.begin()->first;
		}

		ea_t max_ea() const
		{
			return _addrs.empty() ? BADADDR : _addrs.rbegin()->first;
		}

		ea_t xy_to_ea(uint64_t x, uint64_t y) const
		{
			if (y >= _data.size())
			{
				return BADADDR;
			}

			for (auto& e : _data[y])
			{
				if (e.x <= x && x < (e.x + e.body.size()))
				{
					return e.addr;
				}
			}

			return BADADDR;
		}

		ea_t y_to_ea(uint64_t y) const
		{
			return xy_to_ea(0, y);
		}

		ea_t prev_ea(ea_t ea) const
		{
			if (ea > max_ea())
			{
				return max_ea();
			}

			auto it = _addrs.lower_bound(ea);
			--it;
			return it == _addrs.end() ? BADADDR : it->first;
		}

		ea_t adjust_ea(ea_t ea) const
		{
			if (_addrs.count(ea))
			{
				return ea;
			}
			if (ea <= min_ea())
			{
				return min_ea();
			}
			return prev_ea(ea);
		}

		ea_t next_ea(ea_t ea) const
		{
			auto it = _addrs.upper_bound(ea);
			return it == _addrs.end() ? BADADDR : it->first;
		}

		std::pair<uint64_t, uint64_t> ea_to_xy(ea_t ea) const
		{
			ea = adjust_ea(ea);
			auto it = _addrs.find(ea);
			return it == _addrs.end()
					? std::make_pair<uint64_t, uint64_t>(0, 0)
					: it->second;
		}
		uint64_t ea_to_x(ea_t ea) const
		{
			return ea_to_xy(ea).first;
		}
		uint64_t ea_to_y(ea_t ea) const
		{
			return ea_to_xy(ea).second;
		}

		std::vector<std::string> ea_to_lines(ea_t ea)
		{
			std::vector<std::string> ret;

			for (auto& l : _data)
			{
				if (!l.empty() && l.front().addr == ea)
				{
					std::string lineStr;
					for (auto& e : l)
					{
						lineStr += e.body;
					}
					ret.push_back(lineStr);
				}
			}

			return ret;
		}
};

test_data_t* global_data = nullptr;

//==============================================================================

class test_place_t : public place_t
{
	private:
		test_data_t* _data = nullptr;
		ea_t _ea = 0;

	public:
		test_place_t(test_data_t* d, ea_t ea) :
				_data(d),
				_ea(ea)
		{
			lnnum = 0;
		}

	public:
		uint64_t x() const
		{
			return _data->ea_to_x(_ea);
		}
		uint64_t y() const
		{
			return _data->ea_to_y(_ea);
		}

		ea_t ea() const
		{
			return _ea;
		}

	public:
		/// Generate a short description of the location.
		/// This description is used on the status bar.
		/// \param out_buf  the output buffer
		/// \param ud       pointer to user-defined context data.
		///                 Is supplied by ::linearray_t
		virtual void idaapi print(qstring *out_buf, void *ud) const override
		{
			static unsigned cntr = 0;

			qstring ea_str;
			ea2str(&ea_str, ea());

			std::string str = std::string("hello @ ")
					+ ea_str.c_str()
					+ " @ "
					+ std::to_string(y()) + ":" + std::to_string(x());
			*out_buf = str.c_str();
		}

		/// Map the location to a number.
		/// This mapping is used to draw the vertical scrollbar.
		/// \param ud  pointer to user-defined context data.
		/// Is supplied by ::linearray_t
		virtual uval_t idaapi touval(void *ud) const override
		{
			return y();
		}

		/// Clone the location.
		/// \return a pointer to a copy of the current location in dynamic
		/// memory
		virtual place_t *idaapi clone(void) const override
		{
			return new test_place_t(*this);
		}

		/// Copy the specified location object to the current object
		virtual void idaapi copyfrom(const place_t *from) override
		{
			test_place_t *s = (test_place_t*) from;
			lnnum     = s->lnnum;
			_data     = s->_data;
			_ea       = s->_ea;
		}

		/// Map a number to a location.
		/// When the user clicks on the scrollbar and drags it, we need to
		/// determine the location corresponding to the new scrollbar position.
		/// This function is used to determine it. It builds a location object
		/// for the specified 'x' and returns a pointer to it.
		/// \param ud     pointer to user-defined context data.
		///               Is supplied by ::linearray_t
		/// \param x      number to map
		/// \param lnnum  line number to initialize 'lnnum'
		/// \return a static object, no need to destroy it.
		virtual place_t *idaapi makeplace(
				void *ud,
				uval_t x,
				int lnnum) const override
		{
			static test_place_t p(_data, _data->y_to_ea(x));
			p.lnnum = lnnum;
			return &p;
		}

		/// Compare two locations except line numbers (lnnum).
		/// This function is used to organize loops.
		/// For example, if the user has selected an range, its boundaries are
		/// remembered as location objects. Any operation within the selection
		/// will have the following look:
		/// for ( loc=starting_location; loc < ending_location; loc.next() )
		/// In this loop, the comparison function is used.
		/// \retval -1 if the current location is less than 't2'
		/// \retval  0 if the current location is equal to than 't2'
		/// \retval  1 if the current location is greater than 't2'
		virtual int idaapi compare(const place_t *t2) const override
		{
			test_place_t *s = (test_place_t*) t2;
			if (ea() < s->ea()) return -1;
			else if (ea() > s->ea()) return 1;
			else return 0;
		}

		/// Adjust the current location to point to a displayable object.
		/// This function validates the location and makes sure that it points
		/// to an existing object. For example, if the location points to the
		/// middle of an instruction, it will be adjusted to point to the
		/// beginning of the instruction.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		virtual void idaapi adjust(void *ud) override
		{
			_ea = _data->adjust_ea(ea());
		}

		/// Move to the previous displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi prev(void *ud) override
		{
			if (ea() <= _data->min_ea())
			{
				return false;
			}
			_ea = _data->prev_ea(ea());
			return true;
		}

		/// Move to the next displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi next(void *ud) override
		{
			if (ea() >= _data->max_ea())
			{
				return false;
			}
			_ea = _data->next_ea(ea());
			return true;
		}

		/// Are we at the first displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the first
		///         displayable object
		virtual bool idaapi beginning(void *ud) const override
		{
			return ea() == _data->min_ea();
		}

		/// Are we at the last displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the last
		///         displayable object
		virtual bool idaapi ending(void *ud) const override
		{
			return ea() == _data->max_ea();
		}

		/// Generate text lines for the current location.
		/// \param out            storage for the lines
		/// \param out_deflnnum   pointer to the cell that will contain the num
		///                       of the most 'interesting' generated line
		/// \param out_pfx_color  pointer to the cell that will contain the
		///                       line prefix color
		/// \param out_bgcolor    pointer to the cell that will contain the
		///                       background color
		/// \param ud             pointer to user-defined context data.
		///                       Is supplied by linearray_t
		/// \param maxsize        the maximum number of lines to generate
		/// \return number of generated lines
		virtual int idaapi generate(
				qstrvec_t *out,
				int *out_deflnnum,
				color_t *out_pfx_color,
				bgcolor_t *out_bgcolor,
				void *ud,
				int maxsize) const override
		{
			if (maxsize <= 0)
			{
				return 0;
			}

			auto lines = _data->ea_to_lines(ea());
			for (auto& l : lines)
			{
				out->push_back(l.c_str());
			}

			*out_deflnnum = 0;
			return lines.size();
		}

		/// Serialize this instance.
		/// It is fundamental that all instances of a particular subclass
		/// of of place_t occupy the same number of bytes when serialized.
		/// \param out   buffer to serialize into
		virtual void idaapi serialize(bytevec_t *out) const override
		{
			place_t__serialize(this, out);
			append_ea(*out, this->ea());
		}

		/// De-serialize into this instance.
		/// 'pptr' should be incremented by as many bytes as
		/// de-serialization consumed.
		/// \param pptr pointer to a serialized representation of a place_t
		///             of this type.
		/// \param end pointer to end of buffer.
		/// \return whether de-serialization was successful
		virtual bool idaapi deserialize(
				const uchar **pptr,
				const uchar *end) override
		{
			if (!place_t__deserialize(this, pptr, end) || *pptr >= end)
			{
				return false;
			}
			this->_ea = unpack_ea(pptr, end);
			return true;
		}

		/// Get the place's ID (i.e., the value returned by
		/// register_place_class())
		/// \return the id
		virtual int idaapi id() const override
		{
			return test_place_id;
		}

		/// Get this place type name.
		/// All instances of a given class must return the same string.
		/// \return the place type name. Please try and pick something that is
		///         not too generic, as it might clash w/ other plugins. A good
		///         practice is to prefix the class name with the name
		///         of your plugin. E.g., "myplugin:srcplace_t".
		virtual const char *idaapi name() const override
		{
			return "test_place_t";
		}

		/// Map the location to an ea_t.
		/// \return the corresponding ea_t, or BADADDR;
		virtual ea_t idaapi toea() const
		{
			return ea();
		}

		/// Rebase the place instance
		/// \param infos the segments that were moved
		/// \return true if place was rebased, false otherwise
		virtual bool idaapi rebase(const segm_move_infos_t& /*infos*/ ) override
		{
			return false;
		}

		/// Visit this place, possibly 'unhiding' a section of text.
		/// If entering that place required some expanding, a place_t
		/// should be returned that represents that section, plus some
		/// flags for later use by 'leave()'.
		/// \param out_flags flags to be used together with the place_t that is
		///                  returned, in order to restore the section to its
		///                  original state when leave() is called.
		/// \return a place_t corresponding to the beginning of the section
		///         of text that had to be expanded. That place_t's leave() will
		///         be called with the flags contained in 'out_flags' when the
		///         user navigates away from it.
		virtual place_t *idaapi enter(uint32 * /*out_flags*/) const override
		{
			return nullptr;
		}

		/// Leave this place, possibly 'hiding' a section of text that was
		/// previously expanded (at enter()-time.)
		virtual void idaapi leave(uint32 /*flags*/) const override
		{
			// nothing
		}
};

static test_place_t _template(nullptr, 0);
static idaplace_t _idaplace;

//==============================================================================

struct test_info_t
{
	test_info_t(const test_data_t& hd) :
			data(hd)
	{

	}

	TWidget* cv = nullptr;
	TWidget* testview = nullptr;
	test_data_t data;
};

//==============================================================================

// custom_viewer_adjust_place_t
void idaapi cv_adjust_place(TWidget *v, lochist_entry_t *loc, void *ud)
{
	test_data_t* data = (test_data_t*)ud;

	loc->set_place(test_place_t(
			data,
			data->xy_to_ea(
					loc->renderer_info().pos.cx,
					((test_place_t*)loc->place())->y())
	));
}

static const custom_viewer_handlers_t handlers(
		nullptr,     // keyboard
		nullptr,     // popup
		nullptr,     // mouse_moved
		nullptr,     // click
		nullptr,     // dblclick
		nullptr,     // current position change
		nullptr,     // close
		nullptr,     // help
		cv_adjust_place,     // adjust_place
		nullptr,     // get_place_xcoord
		nullptr,     // location_changed
		nullptr      // can_navigate
);

//==============================================================================

// lochist_entry_cvt_t
bool idaapi place_converter(
        lochist_entry_t *dst,
        const lochist_entry_t &src,
        TWidget *view)
{
	// idaplace_t -> test_place_t
	if (src.place()->name() == std::string(_idaplace.name()))
	{
		test_place_t p(global_data, src.place()->toea());
		dst->set_place(p);
		dst->renderer_info().pos.cx = p.x();
		return true;
	}
	// test_place_t -> idaplace_t
	else if (src.place()->name() == std::string(_template.name()))
	{
		idaplace_t p(src.place()->toea(), 0);
		dst->set_place(p);
		return true;
	}
	// should not happen
	else
	{
		return false;
	}
}

//==============================================================================

ssize_t idaapi ui_callback(void *ud, int code, va_list va)
{
	test_info_t *si = (test_info_t*)ud;
	switch (code)
	{
		case ui_widget_invisible:
		{
			TWidget *f = va_arg(va, TWidget *);
			if (f == si->testview || f == si->cv)
			{
				delete si;
				unhook_from_notification_point(HT_UI, ui_callback);
			}
		}
		break;
	}

	return 0;
}

//==============================================================================

bool idaapi run(size_t)
{
	test_place_id = register_place_class(&_template, 0, &PLUGIN);
	register_loc_converter(_template.name(), _idaplace.name(), place_converter);

	static const char title[] = "Places testview";
	TWidget *widget = find_widget(title);
	if (widget != nullptr)
	{
		warning("Places testview already open. Switching to it.");
		activate_widget(widget, true);
		return true;
	}

	test_data_t data(fnc_ack);

	test_info_t* si = new test_info_t(data);

	test_place_t s1(&si->data, si->data.min_ea());
	test_place_t s2(&si->data, si->data.max_ea());

	si->cv = create_custom_viewer(
			title,      // title
			&s1,        // minplace
			&s2,        // maxplace
			&s1,        // curplace
			nullptr,    // rinfo
			&si->data,  // ud
			&handlers,  // handlers
			&si->data,  // cvhandlers_ud
			nullptr     // parent widget
	);

	si->testview = create_code_viewer(si->cv);

	hook_to_notification_point(HT_UI, ui_callback, si);

	display_widget(si->testview, WOPN_TAB|WOPN_MENU|WOPN_RESTORE);

	return true;
}

int idaapi init(void)
{
	return PLUGIN_KEEP;
}

void idaapi term(void)
{

}

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,                    // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	"places test",        // long comment about the plugin
	"places test",        // multiline help about the plugin
	"places test",        // the preferred short name of the plugin
	"Ctrl-d"              // the preferred hotkey to run the plugin
};

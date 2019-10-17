
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

struct Token
{
	std::string body;
	ea_t addr;
};

using Line = std::vector<Token>;

class Function
{
	public:
		ea_t start;
		ea_t end;
		std::vector<Line> lines;

	public:
		bool operator<(const Function& rhs) const
		{
			return start < rhs.start;
		}
};

Function fnc_ack =
{
	0x804851C,
	0x8048577,
	{
		{ {"int __cdecl ack(int a1, int a2)", 0x804851C} },
		{ {"{", 0x804851C} },
		{ {"  int v3; // eax", 0x804851C} },
		{ {"", 0x804851C} },
		{ {"  if ( !a1 )", 0x8048526} },
		{ {"    return a2 + 1;", 0x804852B} },
		{ {"  if ( !a2 )", 0x8048534} },
		{ {"    return ack(", 0x8048547},
		  {"a1 - ", 0x8048544},
		  {"1, ", 0x8048539},
		  {"1);", 0x804853C} },
		{ {"  v3 = ack(", 0x804855E},
		  {"a1, ", 0x804855B},
		  {"a2 - ", 0x8048554},
		  {"1);", 0x8048551} },
		{ {"  return ", 0x8048575},
		  {"ack(", 0x8048570},
		  {"a1 - ", 0x804856D},
		  {"1, ", 0x8048566},
		  {"v3);", 0x8048569} },
		{ {"}", 0x8048575} },
	}
};

Function fnc_main =
{
	0x8048577,
	0x80485F6,
	{
		{ {"int __cdecl main(int argc, const char **argv, const char **envp)", 0x8048577} },
		{ {"{", 0x8048577} },
		{ {"  int v4; // [esp+14h] [ebp-Ch]", 0x8048577} },
		{ {"  int v5; // [esp+18h] [ebp-8h]", 0x8048577} },
		{ {"  int v6; // [esp+1Ch] [ebp-4h]", 0x8048577} },
		{ {"", 0x8048577} },
		{ {"  v6 = 0;", 0x8048580} },
		{ {"  v5 = 0;", 0x8048588} },
		{ {"  v4 = 0;", 0x8048590} },
		{ {"  __isoc99_scanf(", 0x80485AF},
		  {"\"%d %d\", ", 0x80485A8},
		  {"&v5, ", 0x80485A4},
		  {"&v4);", 0x804859C} },
		{ {"  v6 = ", 0x80485C8},
		  {"ack(", 0x80485C3},
		  {"v5, ", 0x80485C0},
		  {"v4);", 0x80485BC} },
		{ {"  printf(", 0x80485EB},
		  {"\"ackerman( %d , %d ) = %d\\n\", ", 0x80485E4},
		  {"v5, ", 0x80485E0},
		  {"v4, ", 0x80485DC},
		  {"v6);", 0x80485D8} },
		{ {"  return v6;", 0x80485F4} },
		{ {"}", 0x80485F4} },
	}
};

using Functions = std::map<ea_t, Function>;
Functions functions = {
	{fnc_ack.start, fnc_ack},
	{fnc_main.start, fnc_main}
};

class Decompiler
{
	public:
		static Function* decompile(ea_t addr)
		{
			auto it = functions.upper_bound(addr);

			if (it == functions.begin())
			{
				// Before the first -> no function.
				return nullptr;
			}
			else if (it == functions.end() && !functions.empty())
			{
				// After the last -> check the last function.
				auto& last = functions.rbegin()->second;
				return last.start <= addr && addr < last.end ? &last : nullptr;
			}
			else if (it != functions.end())
			{
				// In the middle -> check the previous.
				--it;
				auto& prev = it->second;
				return prev.start <= addr && addr < prev.end ? &prev : nullptr;
			}
			else
			{
				return nullptr;
			}
		}
};

//==============================================================================

struct YX
{
	YX() {}
	YX(std::size_t _y, std::size_t _x) : y(_y), x(_x) {}

	bool operator<(const YX& rhs) const
	{
		std::pair<std::size_t, std::size_t> _this(y, x);
		std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
		return _this < other;
	}

	bool operator<=(const YX& rhs) const
	{
		std::pair<std::size_t, std::size_t> _this(y, x);
		std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
		return _this <= other;
	}

	bool operator>(const YX& rhs) const
	{
		std::pair<std::size_t, std::size_t> _this(y, x);
		std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
		return _this > other;
	}

	bool operator>=(const YX& rhs) const
	{
		std::pair<std::size_t, std::size_t> _this(y, x);
		std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
		return _this >= other;
	}

	bool operator==(const YX& rhs) const
	{
		std::pair<std::size_t, std::size_t> _this(y, x);
		std::pair<std::size_t, std::size_t> other(rhs.y, rhs.x);
		return _this == other;
	}

	static std::size_t starting_y()
	{
		return 1;
	}

	static std::size_t starting_x()
	{
		return 0;
	}

	static YX starting_yx()
	{
		return YX(starting_y(), starting_x());
	}

	std::size_t y = YX::starting_y();
	std::size_t x = YX::starting_x();
};

class test_data_t
{
	friend class test_place_t;

	private:
		std::map<YX, Token> _tokens;
		std::map<ea_t, YX> _addr2yx;

	public:
		test_data_t(Function& f)
		{
			std::size_t y = YX::starting_y();
			for (auto& l : f.lines)
			{
				std::size_t x = YX::starting_x();
				for (auto& e : l)
				{
					if (_addr2yx.count(e.addr) == 0)
					{
						_addr2yx[e.addr] = YX(y, x);
					}
					_tokens.emplace(YX(y, x), e);

					x += e.body.size();
				}
				++y;
			}
		}

	public:
		ea_t yx_to_ea(YX yx)
		{
			auto it = _tokens.find(adjust_yx(yx));
			if (it == _tokens.end())
			{
				return BADADDR;
			}
			return it->second.addr;
		}

		YX adjust_yx(YX yx)
		{
			if (_tokens.empty())
			{
				return yx;
			}
			if (_tokens.count(yx))
			{
				return yx;
			}
			if (yx <= min_yx())
			{
				return min_yx();
			}
			if (yx >= max_yx())
			{
				return max_yx();
			}

			auto it = _tokens.upper_bound(yx);
			--it;
			return it->first;
		}

		YX min_yx() const
		{
			return _tokens.empty() ? YX::starting_yx() : _tokens.begin()->first;
		}
		std::size_t min_x() const
		{
			return min_yx().x;
		}
		std::size_t min_y() const
		{
			return min_yx().y;
		}

		YX max_yx() const
		{
			return _tokens.empty() ? YX::starting_yx() : _tokens.rbegin()->first;
		}
		std::size_t max_x() const
		{
			return max_yx().x;
		}
		std::size_t max_y() const
		{
			return max_yx().y;
		}

		YX ea_to_yx(ea_t ea) const
		{
			if (_addr2yx.empty())
			{
				return YX::starting_yx();
			}
			if (ea < _addr2yx.begin()->first || _addr2yx.rbegin()->first < ea)
			{
				return YX::starting_yx();
			}
			if (ea == _addr2yx.rbegin()->first)
			{
				return max_yx();
			}

			auto it = _addr2yx.upper_bound(ea);
			--it;
			return it->second;
		}

		YX prev_yx(YX yx)
		{
			auto it = _tokens.find(adjust_yx(yx));
			if (it == _tokens.end() || it == _tokens.begin())
			{
				return yx;
			}
			--it;
			return it->first;
		}
		YX next_yx(YX yx)
		{
			auto it = _tokens.find(adjust_yx(yx));
			auto nit = it;
			++nit;
			if (it == _tokens.end() || nit == _tokens.end())
			{
				return yx;
			}
			++it;
			return it->first;
		}

		std::string yx_to_line(YX yx)
		{
			std::string ret;

			auto it = _tokens.find(yx);
			while (it != _tokens.end() && it->first.y == yx.y)
			{
				ret += it->second.body;
				++it;
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
		YX _yx;

	public:
		test_place_t(test_data_t* d, YX yx) :
				_data(d),
				_yx(yx)
		{
			lnnum = 0;
		}

	public:
		YX yx() const
		{
			return _yx;
		}
		std::size_t x() const
		{
			return yx().x;
		}
		std::size_t y() const
		{
			return yx().y;
		}

		ea_t ea() const
		{
			return _data->yx_to_ea(yx());
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
			cntr++;

			qstring ea_str;
			ea2str(&ea_str, ea());

			std::string str = std::string("hello @ ")
					+ ea_str.c_str()
					+ " @ "
					+ std::to_string(y()) + ":" + std::to_string(x())
					+ " # " + std::to_string(cntr);
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
			_yx       = s->_yx;
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
				uval_t y,
				int lnnum) const override
		{
			static test_place_t p(_data, {y, 0});
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
			if (yx() < s->yx()) return -1;
			else if (yx() > s->yx()) return 1;
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
			_yx.x = 0;
		}

		/// Move to the previous displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi prev(void *ud) override
		{
			auto pyx = _data->prev_yx(yx());
			if (yx() <= _data->min_yx() || pyx == yx())
			{
				return false;
			}
			_yx = pyx;
			return true;
		}

		/// Move to the next displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi next(void *ud) override
		{
			auto nyx = _data->next_yx(yx());
			if (yx() >= _data->max_yx() || nyx == yx())
			{
				return false;
			}
			_yx = nyx;
			return true;
		}

		/// Are we at the first displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the first
		///         displayable object
		virtual bool idaapi beginning(void *ud) const override
		{
			return yx() == _data->min_yx();
		}

		/// Are we at the last displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the last
		///         displayable object
		virtual bool idaapi ending(void *ud) const override
		{
			return yx() == _data->max_yx();
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
			static unsigned cntr = 0;
			cntr++;

			if (maxsize <= 0)
			{
				return 0;
			}
			if (x() != 0)
			{
				return 0;
			}

			*out_deflnnum = 0;

			std::string str = _data->yx_to_line(yx());
			out->push_back(str.c_str());
			return 1;
		}

		/// Serialize this instance.
		/// It is fundamental that all instances of a particular subclass
		/// of of place_t occupy the same number of bytes when serialized.
		/// \param out   buffer to serialize into
		virtual void idaapi serialize(bytevec_t *out) const override
		{
			place_t__serialize(this, out);
			append_ea(*out, this->y());
			append_ea(*out, this->x());
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
			auto y = unpack_ea(pptr, end);
			auto x = unpack_ea(pptr, end);
			this->_yx = YX(y, x);
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

static test_place_t _template(nullptr, YX(0, 0));
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
			data->adjust_yx(YX(
					((test_place_t*)loc->place())->y(),
					loc->renderer_info().pos.cx
			))
	));
}

// custom_viewer_get_place_xcoord_t
int idaapi cv_get_place_xcoord(TWidget *v, const place_t *pline, const place_t *pitem, void *ud)
{
	test_place_t* mpline = (test_place_t*)pline;
	test_place_t* mpitem = (test_place_t*)pitem;

	if (mpline->y() != mpitem->y())
	{
		return -1; // not included
	}
	// mpline->y() == mpitem->y()
	else if (mpitem->x() == 0)
	{
		return -2; // points to entire line
	}
	else
	{
		return mpitem->x(); // included at coordinate
	}
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
		cv_get_place_xcoord,     // get_place_xcoord
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
		test_place_t p(global_data, global_data->ea_to_yx(src.place()->toea()));
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
	test_place_id = register_place_class(&_template, PCF_EA_CAPABLE, &PLUGIN);
	register_loc_converter(_template.name(), _idaplace.name(), place_converter);

	static const char title[] = "Places testview";
	TWidget *widget = find_widget(title);
	if (widget != nullptr)
	{
		warning("Places testview already open. Switching to it.");
		activate_widget(widget, true);
		return true;
	}

	ea_t addr = get_screen_ea();
	auto fnc = Decompiler::decompile(addr);
	if (fnc == nullptr)
	{
		warning("Cannot decompile function @ %a\n", addr);
		return true;
	}
	test_data_t data(*fnc);

	test_info_t* si = new test_info_t(data);
	global_data = &si->data;

	test_place_t s1(&si->data, si->data.min_yx());
	test_place_t s2(&si->data, si->data.max_yx());

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

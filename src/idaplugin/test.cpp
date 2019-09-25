
#include <cstdint>
#include <map>
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

class test_data_t
{
	friend class test_place_t;

	public:
		test_data_t(std::vector<std::string>& data) :
				_data(data)
		{
			unsigned cntr = 0;
			for (auto& l : _data)
			{
				_pos2line[sz] = cntr++;
				sz += l.size();
			}
		}

	public:
		uval_t maxline() const
		{
			return _data.size() - 1;
		}

		uint64_t size() const
		{
			return sz;
		}

		uval_t pos_to_line(uint64_t pos)
		{
			auto next = _pos2line.upper_bound(pos);
			if (next == _pos2line.begin())
			{
				return 0;
			}

			--next;
			return next->second;
		}

		uint64_t x_y_to_pos(unsigned x, unsigned y)
		{
			uint64_t pos = 0;
			for (std::size_t i = 0; i < y && i < _data.size(); ++i)
			{
				pos += _data[i].size();
			}
			if (y < _data.size())
			{
				if (x < _data[y].size())
				{
					pos += x;
				}
				else
				{
					pos += _data[y].size();
				}
			}
			return pos;
		}

		std::string hello()
		{
			return "hello world";
		}

	public:
		std::vector<std::string>& _data;
		std::map<uint64_t, unsigned> _pos2line;
		uint64_t sz = 0;
};

//==============================================================================

class test_place_t : public place_t
{
	public:
		test_place_t()
		{

		}

		test_place_t(test_data_t* d, uint64_t p = 0) :
				data(d),
				pos(p),
				line(data->pos_to_line(pos))
		{
			lnnum = 0;
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

			std::string str = "shit @ "
					+ std::to_string(line)
					+ " : " + std::to_string(pos)
					+ " # " + std::to_string(cntr++);
			*out_buf = str.c_str();
		}

		/// Map the location to a number.
		/// This mapping is used to draw the vertical scrollbar.
		/// \param ud  pointer to user-defined context data.
		/// Is supplied by ::linearray_t
		virtual uval_t idaapi touval(void *ud) const override
		{
			return line;
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
			data      = s->data;
			pos       = s->pos;
			line      = s->line;
			lnnum     = s->lnnum;
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
			static test_place_t p;
			p.data  = data;
			p.line  = x;
			p.pos   = x;
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
			if (line < s->line) return -1;
			else if (line > s->line) return 1;
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
			if (line > data->maxline())
			{
				pos = 0;
				line = 0;
				lnnum = 0;
			}
		}

		/// Move to the previous displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi prev(void *ud) override
		{
			if (line == 0)
			{
				return false;
			}
			line--;
			return true;
		}

		/// Move to the next displayable location.
		/// \param ud  pointer to user-defined context data.
		///            Is supplied by ::linearray_t
		/// \return success
		virtual bool idaapi next(void *ud) override
		{
			if (line >= data->size())
			{
				return false;
			}
			line++;
			return true;
		}

		/// Are we at the first displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the first
		///         displayable object
		virtual bool idaapi beginning(void *ud) const override
		{
			return line == 0;
		}

		/// Are we at the last displayable object?.
		/// \param ud   pointer to user-defined context data.
		///             Is supplied by ::linearray_t
		/// \return true if the current location points to the last
		///         displayable object
		virtual bool idaapi ending(void *ud) const override
		{
			return line == data->size();
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
			if (line > data->maxline() || maxsize <= 0)
			{
				return 0;
			}

			out->push_back(data->_data[line].c_str());

			*out_deflnnum = 0;

			return 1;
		}

		/// Serialize this instance.
		/// It is fundamental that all instances of a particular subclass
		/// of of place_t occupy the same number of bytes when serialized.
		/// \param out   buffer to serialize into
		virtual void idaapi serialize(bytevec_t *out) const override
		{
			place_t__serialize(this, out);
			append_ea(*out, this->pos);
			append_ea(*out, this->line);
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
			this->pos = unpack_ea(pptr, end);
			this->line = unpack_ea(pptr, end);
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
			return "testview:test_place_t";
		}

		/// Map the location to an ea_t.
		/// \return the corresponding ea_t, or BADADDR;
		virtual ea_t idaapi toea() const
		{
			// TODO
			return BADADDR;
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

	public:
		test_data_t* data = nullptr;
		uint64_t pos = 0;
		uval_t line = 0;
};

static test_place_t _template;

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
void idaapi ct_adjust_place(TWidget *v, lochist_entry_t *loc, void *ud)
{
	static unsigned cntr = 0;

	int x = 0;
	int y = 0;

	get_custom_viewer_place(v, false, &x, &y);

	auto* data = (test_data_t*)ud;
	auto* place = (test_place_t*)loc->plce;

	auto pos = data->x_y_to_pos(x, y);

	msg("ct_adjust_place() %d:%d = %d # %d\n", y, x, pos, cntr++);

	place->pos = pos;
}

//==============================================================================

static const custom_viewer_handlers_t handlers(
		nullptr,     // keyboard
		nullptr,     // popup
		nullptr,     // mouse_moved
		nullptr,     // click
		nullptr,     // dblclick
		nullptr,     // current position change
		nullptr,     // close
		nullptr,     // help
		ct_adjust_place,     // adjust_place
		nullptr,     // get_place_xcoord
		nullptr,     // location_changed
		nullptr      // can_navigate
);

//==============================================================================

bool idaapi run(size_t)
{
	msg("hello world\n");

	// register test place
	test_place_id = register_place_class(&_template, 0, &PLUGIN);

	//
	static const char title[] = "Places testview";
	TWidget *widget = find_widget(title);
	if (widget != nullptr)
	{
		warning("Places testview already open. Switching to it.");
		activate_widget(widget, true);
		return true;
	}

	test_data_t data(text_main);

	test_info_t* si = new test_info_t(data);

	msg("data pointer = %a\n", uint64_t(&si->data));

	test_place_t s1(&si->data);
	test_place_t s2(&si->data, si->data.size() - 1);

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

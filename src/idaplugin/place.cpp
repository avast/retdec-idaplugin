
#include <sstream>

#include "context.h"
#include "decompiler.h"
#include "place.h"

static const idaplace_t _idaplace;
static const demo_place_t _template(nullptr, YX());

void idaapi demo_place_t::print(qstring* out_buf, void* ud) const
{
	static unsigned cntr = 0;
	cntr++;

	qstring ea_str;
	ea2str(&ea_str, toea());

	std::string str = std::string("hello @ ")
			+ ea_str.c_str()
			+ " @ "
			+ std::to_string(y()) + ":" + std::to_string(x())
			+ " # " + std::to_string(cntr);
	*out_buf = str.c_str();
}

uval_t idaapi demo_place_t::touval(void* ud) const
{
	return y();
}

place_t* idaapi demo_place_t::clone(void) const
{
	return new demo_place_t(*this);
}

void idaapi demo_place_t::copyfrom(const place_t* from)
{
	auto* p = static_cast<const demo_place_t*>(from);

	lnnum = p->lnnum;
	_fnc = p->_fnc;
	_yx = p->_yx;
}

place_t* idaapi demo_place_t::makeplace(
		void* ud,
		uval_t y,
		int lnnum) const
{
	auto* p = new demo_place_t(_fnc, YX(y, 0));
	p->lnnum = lnnum;
	return p;
}

int idaapi demo_place_t::compare(const place_t* t2) const
{
	return compare2(t2, nullptr);
}

int idaapi demo_place_t::compare2(const place_t* t2, void *ud) const
{
	auto* p = static_cast<const demo_place_t*>(t2);

	if (_fnc == p->_fnc)
	{
		if (yx() < p->yx()) return -1;
		else if (yx() > p->yx()) return 1;
		else return 0;
	}
	// I'm not sure if this can happen (i.e. places from different functions
	// are compared), but better safe than sorry.
	else if (_fnc->getStart() < p->_fnc->getStart())
	{
		return -1;
	}
	else
	{
		return 1;
	}
}

void idaapi demo_place_t::adjust(void* ud)
{
	// No idea if some handling is needed here.
	// It seems to work OK just like this.
	// The following is not working:
	//     _yx = _fnc->adjust_yx(_yx);
	// Sometimes it generates some extra empty lines.
	_yx.x = 0;
}

bool idaapi demo_place_t::prev(void* ud)
{
	auto pyx = _fnc->prev_yx(yx());
	if (yx() <= _fnc->min_yx() || pyx == yx())
	{
		return false;
	}
	_yx = pyx;
	return true;
}

bool idaapi demo_place_t::next(void* ud)
{
	auto nyx = _fnc->next_yx(yx());
	if (yx() >= _fnc->max_yx() || nyx == yx())
	{
		return false;
	}
	_yx = nyx;
	return true;
}

bool idaapi demo_place_t::beginning(void* ud) const
{
	return yx() == _fnc->min_yx();
}

bool idaapi demo_place_t::ending(void* ud) const
{
	return yx() == _fnc->max_yx();
}

int idaapi demo_place_t::generate(
		qstrvec_t* out,
		int* out_deflnnum,
		color_t* out_pfx_color,
		bgcolor_t* out_bgcolor,
		void* ud,
		int maxsize) const
{
	if (maxsize <= 0)
	{
		return 0;
	}
	if (x() != 0)
	{
		return 0;
	}

	*out_deflnnum = 0;

	std::string str = _fnc->line_yx(yx());
	out->push_back(str.c_str());
	return 1;
}

// All members must be serialized and deserialized.
// This is apparently used when places are moved around.
// When I didn't serialize _fnc pointer, I lost the info about it when
// place was set to lochist_entry_t.
// However, this is also used when saving/loading IDB, and so if we store and
// than load function pointer, we are in trouble. Instead we serialize functions
// as their addresses and use decompiler to get an actual function pointer.
void idaapi demo_place_t::serialize(bytevec_t* out) const
{
	place_t__serialize(this, out);
	out->pack_ea(_fnc->getStart());
	out->pack_ea(y());
	out->pack_ea(x());
}

bool idaapi demo_place_t::deserialize(
		const uchar** pptr,
		const uchar* end)
{
	if (!place_t__deserialize(this, pptr, end) || *pptr >= end)
	{
		return false;
	}
	auto fa = unpack_ea(pptr, end);
	_fnc = Decompiler::decompile(fa);
	auto y = unpack_ea(pptr, end);
	auto x = unpack_ea(pptr, end);
	_yx = YX(y, x);
	return true;
}

int idaapi demo_place_t::id() const
{
	return demo_place_t::ID;
}

const char* idaapi demo_place_t::name() const
{
	return demo_place_t::_name;
}

ea_t idaapi demo_place_t::toea() const
{
	return _fnc->yx_2_ea(yx());
}

bool idaapi demo_place_t::rebase(const segm_move_infos_t&)
{
	// nothing
	return false;
}

place_t* idaapi demo_place_t::enter(uint32*) const
{
	// nothing
	return nullptr;
}

void idaapi demo_place_t::leave(uint32) const
{
	// nothing
}

int demo_place_t::ID = -1;

demo_place_t::demo_place_t(Function* fnc, YX yx)
		: _fnc(fnc)
		, _yx(yx)
{
	lnnum = 0;
}

void demo_place_t::registerPlace(const plugin_t& PLUGIN)
{
	demo_place_t::ID = register_place_class(
			&_template,
			PCF_EA_CAPABLE | PCF_MAKEPLACE_ALLOCATES,
			&PLUGIN
	);

	/// Register a converter, that will be used for the following reasons:
	/// - determine what view can be synchronized with what other view
	/// - when views are synchronized, convert the location from one view,
	///   into an appropriate location in the other view
	/// - if one of p1 or p2 is "idaplace_t", and the other is PCF_EA_CAPABLE,
	///   then the converter will also be called when the user wants to jump to
	///   an address (e.g., by pressing "g"). In that case, from's place_t's lnnum
	///   will be set to -1 (i.e., can be used to descriminate between proper
	///   synchronizations, and jump to's if needed.)
	///
	/// Note: the converter can be used to convert in both directions, and can be
	/// called with its 'from' being of the class of 'p1', or 'p2'.
	/// If you want your converter to work in only one direction (e.g., from
	/// 'my_dictionary_place_t' -> 'my_definition_place_t'), you can have it
	/// return false when it is called with a lochist_entry_t's whose place is
	/// of type 'my_definition_place_t'.
	///
	/// Note: Whenever one of the 'p1' or 'p2' places is unregistered,
	/// corresponding converters will be automatically unregistered as well.
	register_loc_converter(
		_template.name(),
		_idaplace.name(),
		place_converter
	);
}

YX demo_place_t::yx() const
{
	return _yx;
}

std::size_t demo_place_t::y() const
{
	return yx().y;
}

std::size_t demo_place_t::x() const
{
	return yx().x;
}

const Token* demo_place_t::token() const
{
	return fnc()->getToken(yx());
}

Function* demo_place_t::fnc() const
{
	return _fnc;
}

std::string demo_place_t::toString() const
{
	std::stringstream ss;
	ss << *this;
	return ss.str();
}

std::ostream& operator<<(std::ostream& os, const demo_place_t& p)
{
	os << *p.fnc() << p.yx();
	return os;
}

lecvt_code_t idaapi place_converter(
        lochist_entry_t* dst,
        const lochist_entry_t& src,
        TWidget* view)
{
	// idaplace_t -> demo_place_t
	if (src.place()->name() == std::string(_idaplace.name()))
	{
		auto idaEa = src.place()->toea();

		auto* cur = dynamic_cast<demo_place_t*>(get_custom_viewer_place(
						view,
						false, // mouse
						nullptr, // x
						nullptr // y
		));
		if (cur == nullptr)
		{
			return LECVT_ERROR;
		}

		if (cur->fnc()->ea_inside(idaEa))
		{
			demo_place_t p(cur->fnc(), cur->fnc()->ea_2_yx(idaEa));
			dst->set_place(p);
			// Set both x and y, see renderer_info_t comment in demo.cpp.
			dst->renderer_info().pos.cy = p.y();
			dst->renderer_info().pos.cx = p.x();
		}
		else if (Function* fnc = Decompiler::decompile(idaEa))
		{
			demo_place_t cur(fnc, fnc->ea_2_yx(idaEa));
			dst->set_place(cur);
			// Set both x and y, see renderer_info_t comment in demo.cpp.
			dst->renderer_info().pos.cy = cur.y();
			dst->renderer_info().pos.cx = cur.x();
		}
		else
		{
			return LECVT_CANCELED;
		}

		return LECVT_OK;
	}
	// demo_place_t -> idaplace_t
	else if (src.place()->name() == std::string(_template.name()))
	{
		auto* demoPlc = static_cast<const demo_place_t*>(src.place());
		idaplace_t p(demoPlc->toea(), 0);
		dst->set_place(p);
		return LECVT_OK;
	}
	// should not happen
	else
	{
		return LECVT_CANCELED;
	}
}

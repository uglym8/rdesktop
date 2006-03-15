void xclip_handle_SelectionNotify(XSelectionEvent * event);
void xclip_handle_SelectionRequest(XSelectionRequestEvent * xevent);
void xclip_handle_SelectionClear(void);
void xclip_handle_PropertyNotify(XPropertyEvent * xev);
int ewmh_get_window_state(Window w);
int ewmh_change_state(Window wnd, int state);
int ewmh_move_to_desktop(Window wnd, unsigned int desktop);
int ewmh_get_window_desktop(Window wnd);
void ewmh_set_window_popup(Window wnd);

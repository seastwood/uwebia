from main import db, PublicPageContent, PageSection, Picture, CalendarEvent

# Create an example PublicPageContent
page_content = PublicPageContent(site_active_status=True)
db.session.add(page_content)
db.session.commit()

# # Create an example PageSection
# section = PageSection(section_type="ExampleType", order=1, content={"key": "value"}, page_content_id=page_content.id)
# db.session.add(section)
# db.session.commit()

# # Create an example Picture
# picture = Picture(url="http://example.com/pic.jpg", order=1, page_content_id=page_content.id, section_id=section.id)
# db.session.add(picture)
# db.session.commit()

# # Create an example CalendarEvent
# event = CalendarEvent(
#     title="Example Event", description="This is an example event.",
#     start="2023-01-01 00:00:00", end="2023-01-01 23:59:59",
#     all_day=False, background_color="#FF0000", section_id=section.id
# )
# db.session.add(event)
# db.session.commit()

print("Database initialized with example data.")

from ... import schemas

def tag_list_response_serialize(tags: list) -> schemas.TagListResponse:
    return schemas.TagListResponse(tags=[schemas.Tag(id=tag.id, name=tag.name, value=tag.value) for tag in tags])

def tag_create_request_deserialize(body) -> schemas.TagCreateRequest:
    return schemas.TagCreateRequest.model_validate_json(body)

def tag_create_response_serialize(tag) -> schemas.TagCreateResponse:
    return schemas.TagCreateResponse(id=tag.id, name=tag.name, value=tag.value)

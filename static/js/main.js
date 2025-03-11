$(document).ready(function () {
    // 1) 드롭다운 버튼 클릭 시, hidden 클래스를 토글
    $('#dropdownButton').on('click', function (e) {
        e.stopPropagation();              // 클릭 이벤트 전파 중단
        $('#dropdownMenu').toggleClass('hidden'); // hidden 클래스 제거/적용
    });

    // 2) 문서 클릭 시, #dropdownContainer 바깥을 누르면 드롭다운 닫기
    $(document).on('click', function (e) {
        if (!$(e.target).closest('#dropdownContainer').length) {
            $('#dropdownMenu').addClass('hidden');
        }
    });

});